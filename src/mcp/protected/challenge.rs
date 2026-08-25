use serde_json::json;

use super::McpProtectedRequestError;

/// RFC 6750/RFC 9449 challenge rendered with Better Auth's MCP JSON-RPC body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAuthorizationChallenge {
    pub status_code: u16,
    pub message: String,
    pub www_authenticate: String,
}

impl McpAuthorizationChallenge {
    pub fn content_type(&self) -> &'static str {
        "application/json"
    }

    pub fn json_rpc_body(&self) -> String {
        json!({
            "jsonrpc": "2.0",
            "error": { "code": -32_000, "message": self.message },
            "id": Value::Null,
        })
        .to_string()
    }
}

use serde_json::Value;

pub(super) fn from_oauth_error(
    error: &crate::OAuthProviderError,
    resource: &str,
    challenge_scopes: Option<&[String]>,
    dpop_algorithms: Option<&[String]>,
) -> Result<McpAuthorizationChallenge, McpProtectedRequestError> {
    let options = crate::OAuthResourceServerChallengeOptions {
        challenge_scopes: challenge_scopes.map(<[String]>::to_vec),
        dpop_signing_algorithms: dpop_algorithms.map(<[String]>::to_vec),
        ..Default::default()
    };
    let challenge = crate::create_oauth_resource_server_challenge(error, &[resource], &options)
        .map_err(|error| McpProtectedRequestError::InvalidConfiguration(error.to_string()))?
        .ok_or_else(|| {
            McpProtectedRequestError::Infrastructure(
                "authorization failure cannot be converted into an MCP challenge".into(),
            )
        })?;
    Ok(McpAuthorizationChallenge {
        status_code: challenge.status_code,
        message: challenge.message,
        www_authenticate: challenge.www_authenticate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exact_json_rpc_challenge_shape() {
        let challenge = from_oauth_error(
            &crate::OAuthProviderError::InvalidToken("missing authorization header".into()),
            "https://api.example.test/mcp",
            Some(&["mcp:read".into()]),
            None,
        )
        .unwrap();
        assert_eq!(challenge.status_code, 401);
        assert_eq!(
            challenge.www_authenticate,
            "Bearer resource_metadata=\"https://api.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:read\""
        );
        assert_eq!(
            challenge.json_rpc_body(),
            r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"missing authorization header"},"id":null}"#
        );
    }
}
