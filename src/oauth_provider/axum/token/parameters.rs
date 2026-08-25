#[derive(Default)]
struct Parameters(BTreeMap<String, Vec<String>>);

impl Parameters {
    fn first(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .and_then(|values| values.iter().find(|value| !value.is_empty()))
            .map(String::as_str)
    }

    fn all(&self, name: &str) -> Option<Vec<String>> {
        self.0
            .get(name)
            .filter(|values| !values.is_empty())
            .cloned()
    }
}

async fn parameters(
    request: Request,
) -> Result<(HeaderMap, Method, Parameters), OAuthProviderError> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| OAuthProviderError::InvalidRequest("request body is too large".into()))?;
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or("");
    if !content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return Err(OAuthProviderError::UnsupportedMediaType(format!(
            "Content-Type \"{content_type}\" is not allowed. Allowed types: application/x-www-form-urlencoded"
        )));
    }
    let mut parsed = Parameters::default();
    for (name, value) in url::form_urlencoded::parse(&bytes) {
        parsed
            .0
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    Ok((parts.headers, parts.method, parsed))
}
