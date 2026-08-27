use super::DeviceAuthorizationGenerationError;
use url::Url;

pub fn build_verification_uris(
    verification_uri: Option<&str>,
    base_url: &str,
    user_code: &str,
) -> Result<(String, String), DeviceAuthorizationGenerationError> {
    let uri = verification_uri.unwrap_or("/device");
    let verification = match Url::parse(uri) {
        Ok(url) => url,
        Err(_) => Url::parse(base_url)
            .and_then(|base| base.join(uri))
            .map_err(|_| DeviceAuthorizationGenerationError::InvalidVerificationUri)?,
    };
    let mut complete = verification.clone();
    let retained = complete
        .query_pairs()
        .filter(|(name, _)| name != "user_code")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    complete
        .query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair("user_code", user_code);
    Ok((verification.into(), complete.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_matches_javascript_urls() {
        assert_eq!(
            build_verification_uris(
                Some("verify?theme=dark"),
                "https://auth.example.test/api/auth/",
                "AB CD"
            )
            .unwrap(),
            (
                "https://auth.example.test/api/auth/verify?theme=dark".into(),
                "https://auth.example.test/api/auth/verify?theme=dark&user_code=AB+CD".into()
            )
        );
        assert_eq!(
            build_verification_uris(None, "https://auth.example.test/api/auth", "ABCD")
                .unwrap()
                .0,
            "https://auth.example.test/device"
        );
    }
}
