use crate::creem::{
    CreemCheckoutCustomer, CreemCheckoutRequest, CreemCustomField, CreemMetadata, CreemStore,
};
#[cfg(test)]
use serde_json::Map;
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct CreemCheckoutInput {
    pub product_id: String,
    pub request_id: Option<String>,
    pub units: Option<f64>,
    pub discount_code: Option<String>,
    pub customer_email: Option<String>,
    pub custom_fields: Option<Vec<CreemCustomField>>,
    pub custom_field: Option<Vec<CreemCustomField>>,
    pub success_url: Option<String>,
    pub metadata: Option<CreemMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreemCheckoutSession {
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CreemCheckoutHeaders {
    pub host: Option<String>,
    pub forwarded_host: Option<String>,
    pub forwarded_proto: Option<String>,
    pub forwarded_protocol: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CreemCheckoutError {
    #[error("Creem checkout success URL could not be resolved")]
    InvalidSuccessUrl,
}

pub(crate) async fn prepare_checkout(
    input: CreemCheckoutInput,
    session: Option<&CreemCheckoutSession>,
    default_success_url: Option<&str>,
    headers: &CreemCheckoutHeaders,
    store: Option<&dyn CreemStore>,
) -> Result<CreemCheckoutRequest, CreemCheckoutError> {
    let user_had_trial = match (session, store) {
        (Some(session), Some(store)) => match store.find_user(&session.user_id).await {
            Ok(Some(user)) => user.had_trial.as_ref() == Some(&Value::Bool(true)),
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(message = %error, "Creem trial-history lookup failed");
                false
            }
        },
        _ => false,
    };
    build_checkout(input, session, default_success_url, headers, user_had_trial)
}

fn build_checkout(
    input: CreemCheckoutInput,
    session: Option<&CreemCheckoutSession>,
    default_success_url: Option<&str>,
    headers: &CreemCheckoutHeaders,
    user_had_trial: bool,
) -> Result<CreemCheckoutRequest, CreemCheckoutError> {
    let customer_email = truthy(input.customer_email.as_deref())
        .or_else(|| session.and_then(|session| truthy(Some(&session.email))));
    let success_url =
        resolve_success_url(input.success_url.as_deref(), default_success_url, headers)?;
    let mut metadata = input.metadata.unwrap_or_default();
    if let Some(session) = session {
        metadata.insert("referenceId".into(), Value::String(session.user_id.clone()));
    }
    if user_had_trial {
        metadata.insert("skipTrial".into(), Value::Bool(true));
    }

    Ok(CreemCheckoutRequest {
        request_id: input.request_id,
        product_id: input.product_id,
        units: input.units,
        discount_code: input.discount_code,
        customer: customer_email.map(|email| CreemCheckoutCustomer {
            id: None,
            email: Some(email.to_owned()),
        }),
        custom_fields: input.custom_fields.or(input.custom_field),
        success_url,
        metadata: Some(metadata),
    })
}

pub(crate) fn resolve_success_url(
    requested: Option<&str>,
    configured_default: Option<&str>,
    headers: &CreemCheckoutHeaders,
) -> Result<Option<String>, CreemCheckoutError> {
    let Some(value) = truthy(requested).or_else(|| truthy(configured_default)) else {
        return Ok(None);
    };
    if Url::parse(value).is_ok() {
        return Ok(Some(value.to_owned()));
    }
    let Some(host) =
        truthy(headers.host.as_deref()).or_else(|| truthy(headers.forwarded_host.as_deref()))
    else {
        return Ok(Some(value.to_owned()));
    };
    let protocol = truthy(headers.forwarded_proto.as_deref())
        .or_else(|| truthy(headers.forwarded_protocol.as_deref()))
        .unwrap_or("https");
    let base = Url::parse(&format!("{protocol}://{host}"))
        .map_err(|_| CreemCheckoutError::InvalidSuccessUrl)?;
    base.join(value)
        .map(|url| Some(url.to_string()))
        .map_err(|_| CreemCheckoutError::InvalidSuccessUrl)
}

fn truthy(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creem::{
        CreemStoreError, CreemStoredUser, CreemSubscription, CreemSubscriptionPatch,
    };
    use async_trait::async_trait;
    use uuid::Uuid;

    #[test]
    fn checkout_precedence_matches_javascript_truthiness_and_nullish_fields() {
        let input = CreemCheckoutInput {
            product_id: "product_1".into(),
            customer_email: Some(String::new()),
            custom_fields: Some(Vec::new()),
            custom_field: Some(vec![custom_field()]),
            success_url: Some("/done".into()),
            metadata: Some(Map::from_iter([
                ("referenceId".into(), Value::String("caller".into())),
                ("skipTrial".into(), Value::Bool(false)),
            ])),
            ..CreemCheckoutInput::default()
        };
        let request = build_checkout(
            input,
            Some(&CreemCheckoutSession {
                user_id: "user_1".into(),
                email: "session@example.test".into(),
            }),
            Some("/default"),
            &CreemCheckoutHeaders {
                host: Some("internal.test".into()),
                forwarded_host: Some("forwarded.test".into()),
                forwarded_proto: Some("http".into()),
                forwarded_protocol: Some("https".into()),
            },
            true,
        )
        .unwrap();

        assert_eq!(
            request.customer.and_then(|customer| customer.email),
            Some("session@example.test".into())
        );
        assert_eq!(request.custom_fields, Some(Vec::new()));
        assert_eq!(
            request.success_url.as_deref(),
            Some("http://internal.test/done")
        );
        let metadata = request.metadata.unwrap();
        assert_eq!(metadata["referenceId"], "user_1");
        assert_eq!(metadata["skipTrial"], true);
    }

    #[test]
    fn success_url_uses_default_and_header_fallbacks_without_rewriting_absolute_urls() {
        let headers = CreemCheckoutHeaders {
            forwarded_host: Some("proxy.test".into()),
            forwarded_protocol: Some("http".into()),
            ..CreemCheckoutHeaders::default()
        };
        assert_eq!(
            resolve_success_url(Some(""), Some("complete"), &headers).unwrap(),
            Some("http://proxy.test/complete".into())
        );
        assert_eq!(
            resolve_success_url(Some("https://app.test/done"), Some("/ignored"), &headers).unwrap(),
            Some("https://app.test/done".into())
        );
        assert_eq!(
            resolve_success_url(Some("/relative"), None, &CreemCheckoutHeaders::default()).unwrap(),
            Some("/relative".into())
        );
    }

    #[tokio::test]
    async fn only_literal_true_trial_history_overwrites_caller_metadata() {
        for (had_trial, expected) in [
            (Some(Value::Bool(true)), true),
            (Some(Value::String("true".into())), false),
            (Some(Value::Bool(false)), false),
        ] {
            let store = TrialStore {
                had_trial,
                fail: false,
            };
            let request = prepare_checkout(
                CreemCheckoutInput {
                    product_id: "product".into(),
                    metadata: Some(Map::from_iter([("skipTrial".into(), Value::Bool(false))])),
                    ..CreemCheckoutInput::default()
                },
                Some(&CreemCheckoutSession {
                    user_id: "user".into(),
                    email: "user@example.test".into(),
                }),
                None,
                &CreemCheckoutHeaders::default(),
                Some(&store),
            )
            .await
            .unwrap();
            assert_eq!(request.metadata.unwrap()["skipTrial"], expected);
        }

        let request = prepare_checkout(
            CreemCheckoutInput {
                product_id: "product".into(),
                metadata: Some(Map::from_iter([(
                    "skipTrial".into(),
                    Value::String("caller".into()),
                )])),
                ..CreemCheckoutInput::default()
            },
            Some(&CreemCheckoutSession {
                user_id: "user".into(),
                email: "user@example.test".into(),
            }),
            None,
            &CreemCheckoutHeaders::default(),
            Some(&TrialStore {
                had_trial: None,
                fail: true,
            }),
        )
        .await
        .unwrap();
        assert_eq!(request.metadata.unwrap()["skipTrial"], "caller");
    }

    fn custom_field() -> CreemCustomField {
        CreemCustomField {
            field_type: crate::creem::CreemCustomFieldType::Text,
            key: "name".into(),
            label: "Name".into(),
            optional: None,
            text: None,
            checkbox: None,
        }
    }

    struct TrialStore {
        had_trial: Option<Value>,
        fail: bool,
    }

    #[async_trait]
    impl CreemStore for TrialStore {
        async fn find_user(
            &self,
            reference_id: &str,
        ) -> Result<Option<CreemStoredUser>, CreemStoreError> {
            if self.fail {
                return Err(CreemStoreError::Unavailable("trial lookup".into()));
            }
            Ok(Some(CreemStoredUser {
                reference_id: reference_id.into(),
                creem_customer_id: None,
                had_trial: self.had_trial.clone(),
            }))
        }

        async fn set_user_customer_id(&self, _: &str, _: &str) -> Result<(), CreemStoreError> {
            unreachable!()
        }

        async fn set_user_had_trial(&self, _: &str, _: bool) -> Result<(), CreemStoreError> {
            unreachable!()
        }

        async fn create_subscription(
            &self,
            _: CreemSubscription,
        ) -> Result<CreemSubscription, CreemStoreError> {
            unreachable!()
        }

        async fn find_subscription_by_creem_id(
            &self,
            _: &str,
        ) -> Result<Option<CreemSubscription>, CreemStoreError> {
            unreachable!()
        }

        async fn list_subscriptions_by_reference(
            &self,
            _: &str,
        ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
            unreachable!()
        }

        async fn list_subscriptions_by_customer(
            &self,
            _: &str,
        ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
            unreachable!()
        }

        async fn update_subscription(
            &self,
            _: Uuid,
            _: CreemSubscriptionPatch,
        ) -> Result<Option<CreemSubscription>, CreemStoreError> {
            unreachable!()
        }
    }
}
