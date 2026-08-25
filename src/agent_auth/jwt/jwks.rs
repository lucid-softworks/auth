use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use reqwest::header;
use serde_json::Value;
use url::Url;

use super::AgentJwtError;

struct PublicDnsResolver;

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let hostname = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((hostname.as_str(), 0))
                .await?
                .collect::<Vec<SocketAddr>>();
            if addresses.is_empty() || addresses.iter().any(|address| is_internal_ip(address.ip()))
            {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "JWKS hostname resolves to a private or reserved address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

const MAX_URL_LENGTH: usize = 2_048;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_REDIRECTS: usize = 3;

#[derive(Debug, Clone)]
struct CachedJwks {
    keys: Vec<Value>,
    fetched_at: Instant,
}

pub(crate) struct AgentJwksCache {
    client: reqwest::Client,
    ttl: Duration,
    entries: Mutex<HashMap<String, CachedJwks>>,
    secondary: Option<Arc<dyn crate::SecondaryStorage>>,
}

impl AgentJwksCache {
    pub(crate) fn new(
        ttl: Duration,
        secondary: Option<Arc<dyn crate::SecondaryStorage>>,
    ) -> Result<Self, AgentJwtError> {
        let client = reqwest::Client::builder()
            .dns_resolver(PublicDnsResolver)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()
            .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?;
        Ok(Self {
            client,
            ttl,
            entries: Mutex::new(HashMap::new()),
            secondary,
        })
    }

    pub(crate) async fn get_key_by_kid(
        &self,
        jwks_url: &str,
        kid: &str,
    ) -> Result<Option<Value>, AgentJwtError> {
        validate_url(jwks_url)?;
        let keys = match &self.secondary {
            Some(storage) => match storage
                .get(&format!("agent-auth:jwks:{jwks_url}"))
                .await
                .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?
                .and_then(|value| serde_json::from_str::<Vec<Value>>(&value).ok())
            {
                Some(keys) => keys,
                None => self.fetch_and_store(jwks_url).await?,
            },
            None => {
                let cached = self
                    .entries
                    .lock()
                    .map_err(|_| AgentJwtError::JwksFetch("JWKS cache lock failed".into()))?
                    .get(jwks_url)
                    .filter(|entry| entry.fetched_at.elapsed() <= self.ttl)
                    .cloned();
                match cached {
                    Some(entry) => entry.keys,
                    None => self.fetch_and_store(jwks_url).await?,
                }
            }
        };
        if let Some(key) = select_key(&keys, kid) {
            return Ok(Some(key));
        }

        // Upstream refreshes once immediately when a cached or freshly fetched
        // set does not contain the requested kid, allowing key rotation.
        let fresh = self.fetch_and_store(jwks_url).await?;
        Ok(select_key(&fresh, kid))
    }

    async fn fetch_and_store(&self, url: &str) -> Result<Vec<Value>, AgentJwtError> {
        let keys = fetch_keys(&self.client, url).await?;
        if let Some(storage) = &self.secondary {
            storage
                .set(
                    &format!("agent-auth:jwks:{url}"),
                    serde_json::to_string(&keys)
                        .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?,
                    Some(self.ttl.as_secs()),
                )
                .await
                .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?;
        } else {
            self.entries
                .lock()
                .map_err(|_| AgentJwtError::JwksFetch("JWKS cache lock failed".into()))?
                .insert(
                    url.to_owned(),
                    CachedJwks {
                        keys: keys.clone(),
                        fetched_at: Instant::now(),
                    },
                );
        }
        Ok(keys)
    }
}

fn select_key(keys: &[Value], kid: &str) -> Option<Value> {
    keys.iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .cloned()
}

async fn fetch_keys(client: &reqwest::Client, url: &str) -> Result<Vec<Value>, AgentJwtError> {
    let mut current = url.to_owned();
    for redirect_count in 0..=MAX_REDIRECTS {
        validate_url(&current)?;
        let mut response = client
            .get(&current)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?;
        if response.status().is_redirection() {
            if redirect_count == MAX_REDIRECTS {
                return Err(AgentJwtError::JwksFetch(
                    "JWKS exceeded the redirect limit".into(),
                ));
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| AgentJwtError::JwksFetch("JWKS redirect has no location".into()))?;
            current = Url::parse(&current)
                .and_then(|base| base.join(location))
                .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?
                .to_string();
            continue;
        }
        if !response.status().is_success() {
            return Err(AgentJwtError::JwksFetch(format!(
                "{current} responded with status {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(AgentJwtError::JwksFetch(
                "JWKS response is larger than 1048576 bytes".into(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| AgentJwtError::JwksFetch(error.to_string()))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(AgentJwtError::JwksFetch(
                    "JWKS response is larger than 1048576 bytes".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        return parse_keys(&body);
    }
    Err(AgentJwtError::JwksFetch(
        "JWKS exceeded the redirect limit".into(),
    ))
}

fn parse_keys(body: &[u8]) -> Result<Vec<Value>, AgentJwtError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AgentJwtError::JwksFetch(
            "JWKS response is larger than 1048576 bytes".into(),
        ));
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("keys").and_then(Value::as_array).cloned())
        .ok_or_else(|| AgentJwtError::JwksFetch("JWKS response has no keys array".into()))
}

fn validate_url(value: &str) -> Result<(), AgentJwtError> {
    if value.len() > MAX_URL_LENGTH || !value.starts_with("https://") {
        return Err(AgentJwtError::UnsafeJwksUrl);
    }
    let parsed = Url::parse(value).map_err(|_| AgentJwtError::UnsafeJwksUrl)?;
    if parsed.scheme() != "https" || parsed.username() != "" || parsed.password().is_some() {
        return Err(AgentJwtError::UnsafeJwksUrl);
    }
    let hostname = parsed
        .host_str()
        .ok_or(AgentJwtError::UnsafeJwksUrl)?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if is_internal_hostname(&hostname) {
        return Err(AgentJwtError::UnsafeJwksUrl);
    }
    Ok(())
}

fn is_internal_hostname(hostname: &str) -> bool {
    if matches!(hostname, "localhost" | "0.0.0.0")
        || hostname.ends_with(".localhost")
        || hostname.ends_with(".local")
        || hostname.ends_with(".internal")
    {
        return true;
    }
    hostname.parse::<IpAddr>().is_ok_and(is_internal_ip)
}

fn is_internal_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_internal_ipv4(address.octets()),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_internal_ipv4(mapped.octets());
            }
            let segments = address.segments();
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xff00) == 0xff00
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn is_internal_ipv4(octets: [u8; 4]) -> bool {
    matches!(
        octets,
        [0, ..]
            | [10, ..]
            | [100, 64..=127, ..]
            | [127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0, ..]
            | [192, 0, 2, ..]
            | [192, 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, ..]
            | [203, 0, 113, ..]
            | [224..=255, ..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_only_https_public_jwks_urls_without_credentials() {
        assert!(validate_url("https://keys.example.test/jwks.json").is_ok());
        for blocked in [
            "http://keys.example.test/jwks.json",
            "https://localhost/jwks.json",
            "https://127.4.3.2/jwks.json",
            "https://10.0.0.1/jwks.json",
            "https://169.254.10.2/jwks.json",
            "https://100.64.0.1/jwks.json",
            "https://192.0.2.1/jwks.json",
            "https://224.0.0.1/jwks.json",
            "https://[::1]/jwks.json",
            "https://[fd00::1]/jwks.json",
            "https://[::ffff:127.0.0.1]/jwks.json",
            "https://service.internal/jwks.json",
            "https://user:pass@keys.example.test/jwks.json",
        ] {
            assert!(
                matches!(validate_url(blocked), Err(AgentJwtError::UnsafeJwksUrl)),
                "{blocked}"
            );
        }
    }

    #[test]
    fn response_parser_requires_a_bounded_keys_array() {
        assert_eq!(
            parse_keys(br#"{"keys":[{"kid":"one"}]}"#).unwrap(),
            vec![json!({"kid":"one"})]
        );
        assert!(parse_keys(br#"{"keys":{}}"#).is_err());
        assert!(parse_keys(&vec![b'x'; MAX_RESPONSE_BYTES + 1]).is_err());
    }

    #[test]
    fn selection_requires_an_exact_kid() {
        let keys = vec![json!({"kid":"one"}), json!({"kid":"two"})];
        assert_eq!(select_key(&keys, "two"), Some(json!({"kid":"two"})));
        assert_eq!(select_key(&keys, "missing"), None);
    }
}
