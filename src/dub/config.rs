use super::{DubCustomLeadTrack, DubLeadTracker};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub struct DubOptions {
    pub lead_tracker: Arc<dyn DubLeadTracker>,
    pub disable_lead_tracking: bool,
    pub lead_event_name: Option<String>,
    pub custom_lead_track: Option<Arc<dyn DubCustomLeadTrack>>,
    pub oauth: Option<DubOAuthOptions>,
}

impl DubOptions {
    pub fn new(lead_tracker: Arc<dyn DubLeadTracker>) -> Self {
        Self {
            lead_tracker,
            disable_lead_tracking: false,
            lead_event_name: None,
            custom_lead_track: None,
            oauth: None,
        }
    }

    pub(crate) fn event_name(&self) -> &str {
        self.lead_event_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or("Sign Up")
    }
}

impl fmt::Debug for DubOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DubOptions")
            .field("disable_lead_tracking", &self.disable_lead_tracking)
            .field("lead_event_name", &self.lead_event_name)
            .field("has_custom_lead_track", &self.custom_lead_track.is_some())
            .field("oauth", &self.oauth)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DubOAuthOptions {
    client_id: String,
    client_secret: String,
    pub pkce: bool,
}

impl DubOAuthOptions {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            pkce: true,
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }
}

impl fmt::Debug for DubOAuthOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DubOAuthOptions")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("pkce", &self.pkce)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DubLead, DubLeadError};

    fn options() -> DubOptions {
        DubOptions::new(Arc::new(crate::FnDubLeadTracker::new(|_: DubLead| async {
            Ok::<(), DubLeadError>(())
        })))
    }

    #[test]
    fn defaults_and_javascript_truthy_event_name_match_0_0_6() {
        let mut options = options();
        assert!(!options.disable_lead_tracking);
        assert_eq!(options.event_name(), "Sign Up");
        options.lead_event_name = Some(String::new());
        assert_eq!(options.event_name(), "Sign Up");
        options.lead_event_name = Some("Registered".into());
        assert_eq!(options.event_name(), "Registered");
    }

    #[test]
    fn oauth_defaults_pkce_and_debug_redacts_the_secret() {
        let oauth = DubOAuthOptions::new("dub-client", "dub-client-secret");
        assert!(oauth.pkce);
        assert_eq!(oauth.client_id(), "dub-client");
        assert_eq!(oauth.client_secret(), "dub-client-secret");
        assert!(!format!("{oauth:?}").contains("dub-client-secret"));
    }
}
