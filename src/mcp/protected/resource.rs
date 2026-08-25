use super::McpProtectedRequestError;

/// Validates the canonical protected-resource identifier accepted by MCP.
pub(super) fn validate_mcp_resource(resource: &str) -> Result<(), McpProtectedRequestError> {
    let url =
        url::Url::parse(resource).map_err(|_| invalid("MCP resource must be an absolute URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("MCP resource URL must not contain credentials"));
    }
    if resource.contains('#') {
        return Err(invalid("MCP resource URL must not contain a fragment"));
    }
    if resource.contains('?') {
        return Err(invalid(
            "MCP resource URL must not contain a query; to protect a query-carrying resource, verify tokens with verifyAccessTokenRequest and build challenges with createResourceServerChallenge",
        ));
    }
    let loopback = url.host_str().is_some_and(is_mcp_loopback);
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(invalid(
            "MCP resource URL must use HTTPS, except for localhost or loopback IP development URLs",
        ));
    }
    Ok(())
}

fn is_mcp_loopback(host: &str) -> bool {
    if host == "localhost" || host == "[::1]" || host == "::1" {
        return true;
    }
    let octets: Vec<_> = host.split('.').collect();
    octets.len() == 4
        && octets.first() == Some(&"127")
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

fn invalid(message: &str) -> McpProtectedRequestError {
    McpProtectedRequestError::InvalidConfiguration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_mcp_resource_validation() {
        for value in [
            "https://api.example.test/mcp",
            "http://localhost:3000/mcp",
            "http://127.42.0.1/mcp",
            "http://[::1]:3000/mcp",
        ] {
            assert!(validate_mcp_resource(value).is_ok(), "{value}");
        }
        for value in [
            "urn:example:mcp",
            "http://api.example.test/mcp",
            "http://127.example.test/mcp",
            "https://user:pass@api.example.test/mcp",
            "https://api.example.test/mcp?tenant=a",
            "https://api.example.test/mcp#tools",
        ] {
            assert!(validate_mcp_resource(value).is_err(), "{value}");
        }
    }
}
