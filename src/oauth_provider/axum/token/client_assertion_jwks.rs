use josekit::jwk::JwkSet as JoseJwkSet;
use std::{
    collections::BTreeMap as AssertionCacheMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
    time::{Duration as StdDuration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

const JWKS_CACHE_TTL: StdDuration = StdDuration::from_secs(300);
const JWKS_STALE_TTL: StdDuration = StdDuration::from_secs(600);
const JWKS_CACHE_MAX_ENTRIES: usize = 500;
const JWKS_FETCH_TIMEOUT: StdDuration = StdDuration::from_secs(5);
const MAX_JWKS_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct CachedClientJwks {
    jwks: JoseJwkSet,
    fetched_at: Instant,
}

fn client_jwks_cache() -> &'static AsyncMutex<AssertionCacheMap<String, CachedClientJwks>> {
    static CACHE: OnceLock<AsyncMutex<AssertionCacheMap<String, CachedClientJwks>>> =
        OnceLock::new();
    CACHE.get_or_init(|| AsyncMutex::new(AssertionCacheMap::new()))
}

async fn client_jwks(
    service: &AuthService,
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    force_refresh: bool,
) -> Result<JoseJwkSet, OAuthProviderError> {
    if let Some(inline) = client.jwks.as_deref() {
        return parse_public_jwks(inline.as_bytes());
    }
    let uri = client
        .jwks_uri
        .as_deref()
        .ok_or_else(|| OAuthProviderError::InvalidClient("client has no JWKS configured".into()))?;
    let cache_key = format!(
        "{}:{}:{}:{}",
        config.runtime_instance_id,
        client.client_discovery_id.as_deref().unwrap_or("managed"),
        client.client_id,
        uri
    );
    let cached = client_jwks_cache().lock().await.get(&cache_key).cloned();
    if !force_refresh
        && let Some(cached) = &cached
        && cached.fetched_at.elapsed() < JWKS_CACHE_TTL
    {
        return Ok(cached.jwks.clone());
    }
    match fetch_client_jwks(service, config, client, uri).await {
        Ok(jwks) => {
            store_cached_client_jwks(cache_key, jwks.clone()).await;
            Ok(jwks)
        }
        Err(error) if !force_refresh => {
            if let Some(cached) = cached
                && cached.fetched_at.elapsed() < JWKS_STALE_TTL
            {
                return Ok(cached.jwks);
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

async fn store_cached_client_jwks(cache_key: String, jwks: JoseJwkSet) {
    let mut cache = client_jwks_cache().lock().await;
    cache.insert(
        cache_key,
        CachedClientJwks {
            jwks,
            fetched_at: Instant::now(),
        },
    );
    if cache.len() > JWKS_CACHE_MAX_ENTRIES
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, value)| value.fetched_at)
            .map(|(key, _)| key.clone())
    {
        cache.remove(&oldest);
    }
}

fn validate_client_jwks_uri(
    service: &AuthService,
    client: &OAuthProviderClient,
    value: &str,
) -> Result<(), OAuthProviderError> {
    let uri = validate_jwks_uri(value)
        .map_err(|error| OAuthProviderError::InvalidClient(error.into()))?;
    let discovered_same_origin = client.client_discovery_id.is_some()
        && Url::parse(&client.client_id)
            .ok()
            .is_some_and(|client_id| client_id.origin() == uri.origin());
    if !discovered_same_origin && !service.trusts_origin(uri.as_str()) {
        return Err(OAuthProviderError::InvalidClient(
            "client jwks_uri is not trusted".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_registration_jwks_uri(
    service: &AuthService,
    value: &str,
    client_metadata_document_origin: Option<&url::Origin>,
) -> Result<(), String> {
    let uri = validate_jwks_uri(value).map_err(str::to_owned)?;
    if client_metadata_document_origin.is_some_and(|origin| *origin == uri.origin())
        || service.trusts_origin(uri.as_str())
    {
        return Ok(());
    }
    Err("jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin".into())
}

fn validate_jwks_uri(value: &str) -> Result<Url, &'static str> {
    let uri = Url::parse(value).map_err(|_| "jwks_uri must be a valid URL")?;
    if uri.scheme() != "https" {
        return Err("jwks_uri must use HTTPS");
    }
    if !uri.username().is_empty() || uri.password().is_some() {
        return Err("jwks_uri must not contain credentials");
    }
    if uri.fragment().is_some() {
        return Err("jwks_uri must not include a fragment component");
    }
    if uri.host_str().is_none_or(|host| !is_public_routable_host(host)) {
        return Err("jwks_uri must not point to a private or reserved address");
    }
    Ok(uri)
}

fn is_public_routable_host(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split_once(']').map_or(bracketed, |(host, _)| host)
    } else if host.bytes().filter(|byte| *byte == b':').count() == 1 {
        host.split_once(':').map_or(host, |(host, _)| host)
    } else {
        host
    };
    let host = host.split_once('%').map_or(host, |(host, _)| host);
    let lowercase = host.trim_end_matches('.').to_ascii_lowercase();
    if matches!(
        lowercase.as_str(),
        "localhost"
            | "metadata.google.internal"
            | "metadata.goog"
            | "metadata"
            | "instance-data"
            | "instance-data.ec2.internal"
    ) || lowercase.ends_with(".localhost")
    {
        return false;
    }
    lowercase.parse::<IpAddr>().map_or(true, public_routable_ip)
}

fn public_routable_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_routable_ipv4(address),
        IpAddr::V6(address) => public_routable_ipv6(address),
    }
}

fn public_routable_ipv4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    ![
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.0.0.0", 24),
        ("192.0.2.0", 24),
        ("192.88.99.0", 24),
        ("192.168.0.0", 16),
        ("198.18.0.0", 15),
        ("198.51.100.0", 24),
        ("203.0.113.0", 24),
        ("224.0.0.0", 4),
        ("240.0.0.0", 4),
    ]
    .into_iter()
    .any(|(prefix, length)| ipv4_in_range(value, prefix.parse().expect("static IPv4"), length))
}

fn ipv4_in_range(value: u32, prefix: Ipv4Addr, length: u32) -> bool {
    let mask = u32::MAX << (32_u32 - length);
    value & mask == u32::from(prefix) & mask
}

fn public_routable_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return public_routable_ipv4(mapped);
    }
    let value = u128::from(address);
    let in_range = |prefix: &str, length: u32| {
        let prefix = prefix.parse::<Ipv6Addr>().expect("static IPv6");
        let mask = u128::MAX << (128_u32 - length);
        value & mask == u128::from(prefix) & mask
    };
    if [
        ("::", 96),
        ("64:ff9b::", 96),
        ("64:ff9b:1::", 48),
        ("100::", 64),
        ("2001::", 32),
        ("2001:2::", 48),
        ("2001:db8::", 32),
        ("3fff::", 20),
        ("5f00::", 16),
        ("fc00::", 7),
        ("fe80::", 10),
        ("fec0::", 10),
        ("ff00::", 8),
    ]
    .into_iter()
    .any(|(prefix, length)| in_range(prefix, length))
    {
        return false;
    }
    if in_range("2002::", 16) {
        let segments = address.segments();
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        );
        return public_routable_ipv4(embedded);
    }
    true
}

async fn fetch_client_jwks(
    service: &AuthService,
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    uri: &str,
) -> Result<JoseJwkSet, OAuthProviderError> {
    validate_client_jwks_uri(service, client, uri)?;
    if let Some(discovery_id) = client.client_discovery_id.as_deref() {
        for extension in &config.extensions {
            if !extension
                .client_discovery_ids()
                .iter()
                .any(|value| value == discovery_id)
            {
                continue;
            }
            if let Some(response) = extension
                .fetch_client_metadata_resource(discovery_id, uri)
                .await
                .map_err(|_| client_jwks_fetch_error())?
            {
                if response.status != 200
                    || response.body.len() > MAX_JWKS_RESPONSE_BYTES
                    || !response.content_type.as_deref().is_some_and(json_media_type)
                {
                    return Err(client_jwks_fetch_error());
                }
                return parse_public_jwks(&response.body);
            }
        }
        return Err(OAuthProviderError::InvalidClient(
            "client discovery does not provide a metadata resource transport".into(),
        ));
    }
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(JWKS_FETCH_TIMEOUT)
        .build()
        .map_err(|_| client_jwks_fetch_error())?;
    let mut response = http
        .get(uri)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| client_jwks_fetch_error())?;
    if response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|size| size > MAX_JWKS_RESPONSE_BYTES as u64)
        || !response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(json_media_type)
    {
        return Err(client_jwks_fetch_error());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| client_jwks_fetch_error())? {
        if body.len() + chunk.len() > MAX_JWKS_RESPONSE_BYTES {
            return Err(client_jwks_fetch_error());
        }
        body.extend_from_slice(&chunk);
    }
    parse_public_jwks(&body)
}

fn json_media_type(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type
            .to_ascii_lowercase()
            .strip_prefix("application/")
            .is_some_and(|subtype| subtype.ends_with("+json"))
}

fn parse_public_jwks(bytes: &[u8]) -> Result<JoseJwkSet, OAuthProviderError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| client_jwks_fetch_error())?;
    validate_public_jwks(&value).map_err(|_| client_jwks_fetch_error())?;
    JoseJwkSet::from_bytes(bytes).map_err(|_| client_jwks_fetch_error())
}

pub(super) fn validate_registration_jwks(value: &Value) -> Result<(), &'static str> {
    validate_public_jwks(value)
}

fn validate_public_jwks(value: &Value) -> Result<(), &'static str> {
    let keys = value.get("keys").and_then(Value::as_array).ok_or(
        "jwks must be an RFC 7517 JWK Set object with a non-empty keys array",
    )?;
    if keys.is_empty() {
        return Err("jwks must be an RFC 7517 JWK Set object with a non-empty keys array");
    }
    for key in keys {
        let key = key.as_object().ok_or(
            "jwks keys must be supported public JWKs with required key parameters",
        )?;
        if key.get("kty").and_then(Value::as_str) == Some("oct")
            || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|field| key.contains_key(*field))
        {
            return Err("jwks must contain only public asymmetric keys");
        }
        let kty = key.get("kty").and_then(Value::as_str);
        let curve = key.get("crv").and_then(Value::as_str);
        let nonempty = |name| key.get(name).and_then(Value::as_str).is_some_and(|value| !value.is_empty());
        let supported = match kty {
            Some("RSA") => nonempty("n") && nonempty("e"),
            Some("EC") => matches!(curve, Some("P-256" | "P-384" | "P-521"))
                && nonempty("x")
                && nonempty("y"),
            Some("OKP") => curve == Some("Ed25519") && nonempty("x"),
            _ => false,
        };
        if !supported {
            return Err("jwks keys must be supported public JWKs with required key parameters");
        }
        if let Some(algorithm) = key.get("alg") {
            let algorithm = algorithm.as_str().ok_or(
                "jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve",
            )?;
            let compatible = match kty {
                Some("RSA") => matches!(algorithm, "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"),
                Some("EC") => matches!((curve, algorithm), (Some("P-256"), "ES256") | (Some("P-384"), "ES384") | (Some("P-521"), "ES512")),
                Some("OKP") => algorithm == "EdDSA",
                _ => false,
            };
            if !compatible {
                return Err("jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve");
            }
        }
    }
    Ok(())
}

fn client_jwks_fetch_error() -> OAuthProviderError {
    OAuthProviderError::InvalidClient("failed to fetch client JWKS".into())
}
