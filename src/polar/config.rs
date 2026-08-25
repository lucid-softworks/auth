use super::{
    PolarClient, PolarCustomerCreateParamsProvider, PolarProducts, PolarTheme,
    PolarWebhookCallbacks,
};
use std::{fmt, sync::Arc};
use url::Url;

#[derive(Clone)]
pub struct PolarOptions {
    pub client: Arc<dyn PolarClient>,
    pub create_customer_on_sign_up: bool,
    pub get_customer_create_params: Option<Arc<dyn PolarCustomerCreateParamsProvider>>,
    pub features: Vec<PolarFeature>,
}

impl PolarOptions {
    pub fn new(client: Arc<dyn PolarClient>, features: Vec<PolarFeature>) -> Self {
        Self {
            client,
            create_customer_on_sign_up: false,
            get_customer_create_params: None,
            features,
        }
    }

    pub fn checkout(&self) -> Option<&CheckoutOptions> {
        checkout_feature(&self.features)
    }

    pub fn portal(&self) -> Option<&PortalOptions> {
        portal_feature(&self.features)
    }

    pub fn usage(&self) -> Option<&UsageOptions> {
        usage_feature(&self.features)
    }

    pub fn webhooks(&self) -> Option<&WebhooksOptions> {
        webhooks_feature(&self.features)
    }
}

fn checkout_feature(features: &[PolarFeature]) -> Option<&CheckoutOptions> {
    features.iter().rev().find_map(|feature| match feature {
        PolarFeature::Checkout(options) => Some(options),
        _ => None,
    })
}

fn portal_feature(features: &[PolarFeature]) -> Option<&PortalOptions> {
    features.iter().rev().find_map(|feature| match feature {
        PolarFeature::Portal(options) => Some(options),
        _ => None,
    })
}

fn usage_feature(features: &[PolarFeature]) -> Option<&UsageOptions> {
    features.iter().rev().find_map(|feature| match feature {
        PolarFeature::Usage(options) => Some(options),
        _ => None,
    })
}

fn webhooks_feature(features: &[PolarFeature]) -> Option<&WebhooksOptions> {
    features.iter().rev().find_map(|feature| match feature {
        PolarFeature::Webhooks(options) => Some(options),
        _ => None,
    })
}

impl fmt::Debug for PolarOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolarOptions")
            .field(
                "create_customer_on_sign_up",
                &self.create_customer_on_sign_up,
            )
            .field(
                "has_get_customer_create_params",
                &self.get_customer_create_params.is_some(),
            )
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
// Keep feature construction uniform (`PolarFeature::Webhooks(options)`) rather
// than forcing only callback-heavy options behind a public `Box`.
#[allow(clippy::large_enum_variant)]
pub enum PolarFeature {
    Checkout(CheckoutOptions),
    Portal(PortalOptions),
    Usage(UsageOptions),
    Webhooks(WebhooksOptions),
}

#[derive(Debug, Clone, Default)]
pub struct CheckoutOptions {
    pub products: Option<PolarProducts>,
    pub success_url: Option<String>,
    pub return_url: Option<String>,
    pub authenticated_users_only: bool,
    pub theme: Option<PolarTheme>,
}

#[derive(Debug, Clone, Default)]
pub struct UsageOptions {
    pub credit_products: Option<PolarProducts>,
}

#[derive(Debug, Clone, Default)]
pub struct PortalOptions {
    return_url: Option<Url>,
    pub theme: Option<PolarTheme>,
}

impl PortalOptions {
    pub fn new(
        return_url: Option<&str>,
        theme: Option<PolarTheme>,
    ) -> Result<Self, url::ParseError> {
        Ok(Self {
            return_url: return_url.map(Url::parse).transpose()?,
            theme,
        })
    }

    pub fn return_url(&self) -> Option<&Url> {
        self.return_url.as_ref()
    }

    /// Value forwarded to Polar after the adapter's URL construction step.
    pub fn resolved_return_url(&self) -> Option<String> {
        self.return_url.as_ref().map(|url| decode_uri(url.as_str()))
    }
}

#[derive(Clone)]
pub struct WebhooksOptions {
    secret: Arc<str>,
    pub callbacks: PolarWebhookCallbacks,
}

impl WebhooksOptions {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: Arc::from(secret.into()),
            callbacks: PolarWebhookCallbacks::default(),
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for WebhooksOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhooksOptions")
            .field("secret", &"[REDACTED]")
            .field("callbacks", &self.callbacks)
            .finish()
    }
}

fn decode_uri(value: &str) -> String {
    // `decodeURI` leaves escaped URI delimiters intact while decoding spaces
    // and UTF-8. Work directly on bytes so user input cannot collide with a
    // placeholder and the original casing of reserved escapes is retained.
    const RESERVED: &[u8] = b"#$&+,/:;=?@";
    let input = value.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%'
            && let Some(decoded) = input
                .get(index + 1..index + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            if RESERVED.contains(&decoded) {
                output.extend_from_slice(&input[index..index + 3]);
            } else {
                output.push(decoded);
            }
            index += 3;
            continue;
        }
        output.push(input[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_rejects_relative_return_urls_at_construction() {
        assert!(PortalOptions::new(Some("/account"), None).is_err());
    }

    #[test]
    fn portal_matches_url_then_decode_uri_behavior() {
        let portal = PortalOptions::new(
            Some("https://example.com/account%20home?next=a%2Fb"),
            Some(PolarTheme::Dark),
        )
        .unwrap();
        assert_eq!(
            portal.resolved_return_url().as_deref(),
            Some("https://example.com/account home?next=a%2Fb")
        );
    }

    #[test]
    fn portal_decode_does_not_rewrite_user_text_or_reserved_escape_casing() {
        let portal = PortalOptions::new(
            Some("https://example.com/__POLAR_RESERVED_5__?next=a%2fb"),
            None,
        )
        .unwrap();
        assert_eq!(
            portal.resolved_return_url().as_deref(),
            Some("https://example.com/__POLAR_RESERVED_5__?next=a%2fb")
        );
    }

    #[test]
    fn empty_features_are_allowed_and_duplicate_features_are_last_wins() {
        assert!(checkout_feature(&[]).is_none());
        let features = vec![
            PolarFeature::Checkout(CheckoutOptions {
                success_url: Some("/first".into()),
                ..CheckoutOptions::default()
            }),
            PolarFeature::Portal(PortalOptions::default()),
            PolarFeature::Checkout(CheckoutOptions {
                success_url: Some("/last".into()),
                ..CheckoutOptions::default()
            }),
        ];
        assert_eq!(
            checkout_feature(&features).and_then(|options| options.success_url.as_deref()),
            Some("/last")
        );
        assert!(portal_feature(&features).is_some());
        assert!(usage_feature(&features).is_none());
    }
}
