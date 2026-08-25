use std::collections::BTreeSet;

use url::Url;

use super::AgentJwtError;

#[derive(Debug, Clone)]
pub(crate) struct AgentAudience<'a> {
    base_url: &'a str,
    request_host: Option<&'a str>,
    forwarded_proto: Option<&'a str>,
    trust_proxy: bool,
    expected_location: Option<&'a str>,
}

impl<'a> AgentAudience<'a> {
    pub(crate) fn new(
        base_url: &'a str,
        request_host: Option<&'a str>,
        forwarded_proto: Option<&'a str>,
        trust_proxy: bool,
        expected_location: Option<&'a str>,
    ) -> Self {
        Self {
            base_url,
            request_host,
            forwarded_proto,
            trust_proxy,
            expected_location,
        }
    }

    pub(super) fn matches(&self, audience: &[String]) -> Result<bool, AgentJwtError> {
        let parsed = Url::parse(self.base_url).map_err(|_| AgentJwtError::InvalidAudience)?;
        let configured_origin = parsed.origin().ascii_serialization();
        let base = self.base_url.trim_end_matches('/');
        let base_path = parsed.path().trim_end_matches('/');
        let mut accepted = BTreeSet::from([
            configured_origin,
            base.to_owned(),
            format!("{base}/capability/execute"),
        ]);
        if let Some(host) = self.request_host {
            let protocol = if self.trust_proxy {
                self.forwarded_proto
                    .filter(|value| !value.is_empty())
                    .unwrap_or(parsed.scheme())
            } else {
                parsed.scheme()
            };
            let request_origin = format!("{protocol}://{host}");
            accepted.insert(request_origin.clone());
            accepted.insert(format!("{request_origin}{base_path}"));
            accepted.insert(format!("{request_origin}{base_path}/capability/execute"));
        }
        if let Some(location) = self.expected_location {
            accepted.insert(location.to_owned());
        }
        Ok(audience.iter().any(|value| accepted.contains(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_configured_request_and_single_capability_locations() {
        let configured = AgentAudience::new(
            "https://internal.test/api/auth/",
            Some("public.test"),
            Some("https"),
            true,
            Some("https://mail.test/send"),
        );
        for value in [
            "https://internal.test",
            "https://internal.test/api/auth",
            "https://internal.test/api/auth/capability/execute",
            "https://public.test/api/auth/capability/execute",
            "https://mail.test/send",
        ] {
            assert!(configured.matches(&[value.into()]).unwrap(), "{value}");
        }
        assert!(!configured.matches(&["https://other.test".into()]).unwrap());
    }

    #[test]
    fn ignores_forwarded_protocol_without_proxy_trust() {
        let audience = AgentAudience::new(
            "http://internal.test/api/auth",
            Some("public.test"),
            Some("https"),
            false,
            None,
        );
        assert!(audience.matches(&["http://public.test".into()]).unwrap());
        assert!(!audience.matches(&["https://public.test".into()]).unwrap());
    }
}
