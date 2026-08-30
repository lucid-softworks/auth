use async_trait::async_trait;
use std::{collections::BTreeMap, fmt, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdFetchRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub timeout: Duration,
    pub maximum_response_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdFetchResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub redirected: bool,
}

impl CimdFetchResponse {
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CimdFetchError {
    pub message: String,
}

impl CimdFetchError {
    pub fn new(message: impl Into<String>) -> Self { Self { message: message.into() } }
}

#[async_trait]
pub trait CimdMetadataResourceFetcher: Send + Sync {
    async fn fetch(&self, request: CimdFetchRequest) -> Result<CimdFetchResponse, CimdFetchError>;
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeCimdMetadataFetcher;

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl CimdMetadataResourceFetcher for NativeCimdMetadataFetcher {
    async fn fetch(&self, request: CimdFetchRequest) -> Result<CimdFetchResponse, CimdFetchError> {
        fetch_client_metadata_resource(request).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn fetch_client_metadata_resource(
    request: CimdFetchRequest,
) -> Result<CimdFetchResponse, CimdFetchError> {
    use reqwest::{Client, Method, redirect::Policy};
    use std::{net::IpAddr, str::FromStr};

    let url = url::Url::parse(&request.url).map_err(|_| CimdFetchError::new("invalid metadata URL"))?;
    if url.scheme() != "https" { return Err(CimdFetchError::new("CIMD native transport requires an HTTPS URL")); }
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return Err(CimdFetchError::new("CIMD native transport supports only GET and HEAD"));
    }
    let host = url.host_str().ok_or_else(|| CimdFetchError::new("metadata URL has no hostname"))?;
    let lookup_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let port = url.port_or_known_default().unwrap_or(443);
    let request_host = url.port().map_or_else(
        || host.to_owned(),
        |port| format!("{host}:{port}"),
    );
    let addresses = resolve_addresses(lookup_host, port).await?;
    if addresses.iter().any(|address| !crate::network_address::public_routable_ip(address.ip())) {
        return Err(CimdFetchError::new("metadata hostname must resolve only to public-routable addresses"));
    }
    let mut builder = Client::builder().redirect(Policy::none()).timeout(request.timeout);
    if IpAddr::from_str(lookup_host).is_err() {
        builder = builder.resolve(lookup_host, addresses[0]);
    }
    let client = builder.build().map_err(|error| CimdFetchError::new(error.to_string()))?;
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| CimdFetchError::new("invalid metadata request method"))?;
    let mut outbound = client.request(method, url);
    for (name, value) in request.headers {
        if !name.eq_ignore_ascii_case("host") {
            outbound = outbound.header(name, value);
        }
    }
    outbound = outbound.header(reqwest::header::HOST, request_host);
    let mut response = outbound.send().await.map_err(|error| CimdFetchError::new(error.to_string()))?;
    if response
        .content_length()
        .is_some_and(|length| length > request.maximum_response_bytes as u64)
    {
        return Err(CimdFetchError::new(
            "metadata resource exceeds response size limit",
        ));
    }
    let status = response.status().as_u16();
    let headers = response.headers().iter().filter_map(|(name, value)| {
        value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))
    }).collect();
    let redirected = false;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| CimdFetchError::new(error.to_string()))? {
        if body.len().saturating_add(chunk.len()) > request.maximum_response_bytes {
            return Err(CimdFetchError::new("metadata resource exceeds response size limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(CimdFetchResponse { status, headers, body, redirected })
}

#[cfg(not(target_arch = "wasm32"))]
async fn resolve_addresses(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, CimdFetchError> {
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(address, port)]);
    }
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| CimdFetchError::new(error.to_string()))?
        .collect::<Vec<_>>();
    if addresses.is_empty() { return Err(CimdFetchError::new("metadata hostname returned no DNS addresses")); }
    Ok(addresses)
}

impl fmt::Display for CimdFetchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.url)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn request(url: &str, method: &str) -> CimdFetchRequest {
        CimdFetchRequest {
            url: url.into(),
            method: method.into(),
            headers: BTreeMap::new(),
            timeout: Duration::from_millis(100),
            maximum_response_bytes: 64,
        }
    }

    #[tokio::test]
    async fn native_transport_rejects_non_https_and_unsupported_methods_before_io() {
        assert_eq!(
            fetch_client_metadata_resource(request("http://example.com/doc", "GET"))
                .await
                .unwrap_err()
                .to_string(),
            "CIMD native transport requires an HTTPS URL"
        );
        assert_eq!(
            fetch_client_metadata_resource(request("https://example.com/doc", "POST"))
                .await
                .unwrap_err()
                .to_string(),
            "CIMD native transport supports only GET and HEAD"
        );
    }

    #[tokio::test]
    async fn native_transport_rejects_literal_special_use_addresses_before_connecting() {
        for url in [
            "https://127.0.0.1/doc",
            "https://169.254.169.254/latest/meta-data",
            "https://192.0.2.1/doc",
            "https://[::1]/doc",
            "https://[fe80::1]/doc",
            "https://[2001:db8::1]/doc",
        ] {
            let error = fetch_client_metadata_resource(request(url, "GET"))
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "metadata hostname must resolve only to public-routable addresses",
                "{url}"
            );
        }
    }

    #[test]
    fn response_header_lookup_is_case_insensitive() {
        let response = CimdFetchResponse {
            status: 200,
            headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
            body: Vec::new(),
            redirected: false,
        };
        assert_eq!(response.content_type(), Some("application/json"));
    }
}
