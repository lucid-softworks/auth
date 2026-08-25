use crate::{PluginRequestContext, SessionWithUser};
use async_trait::async_trait;
use std::{collections::BTreeMap, fmt, sync::Arc};

pub type TranslationDictionary = BTreeMap<String, String>;
pub type I18nTranslations = BTreeMap<String, TranslationDictionary>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I18nLocaleDetection {
    Header,
    Cookie,
    Session,
    Callback,
}

#[derive(Debug, Clone)]
pub struct I18nLocaleContext {
    pub request: Option<PluginRequestContext>,
    pub session: Option<SessionWithUser>,
}

#[async_trait]
pub trait I18nLocaleResolver: Send + Sync {
    async fn get_locale(&self, context: I18nLocaleContext) -> Option<String>;
}

pub struct SyncI18nLocaleResolver<F>(F);

pub fn sync_i18n_locale_resolver<F>(resolver: F) -> Arc<dyn I18nLocaleResolver>
where
    F: Fn(I18nLocaleContext) -> Option<String> + Send + Sync + 'static,
{
    Arc::new(SyncI18nLocaleResolver(resolver))
}

#[async_trait]
impl<F> I18nLocaleResolver for SyncI18nLocaleResolver<F>
where
    F: Fn(I18nLocaleContext) -> Option<String> + Send + Sync,
{
    async fn get_locale(&self, context: I18nLocaleContext) -> Option<String> {
        (self.0)(context)
    }
}

#[derive(Clone)]
pub struct I18nConfig {
    pub translations: I18nTranslations,
    pub default_locale: String,
    pub detection: Vec<I18nLocaleDetection>,
    pub locale_cookie: String,
    pub user_locale_field: String,
    pub get_locale: Option<Arc<dyn I18nLocaleResolver>>,
}

impl I18nConfig {
    pub fn new(translations: I18nTranslations) -> Result<Self, I18nConfigError> {
        if translations.is_empty() {
            return Err(I18nConfigError);
        }
        Ok(Self {
            translations,
            default_locale: "en".into(),
            detection: vec![I18nLocaleDetection::Header],
            locale_cookie: "locale".into(),
            user_locale_field: "locale".into(),
            get_locale: None,
        })
    }
}

impl fmt::Debug for I18nConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("I18nConfig")
            .field("translations", &self.translations)
            .field("default_locale", &self.default_locale)
            .field("detection", &self.detection)
            .field("locale_cookie", &self.locale_cookie)
            .field("user_locale_field", &self.user_locale_field)
            .field("has_get_locale", &self.get_locale.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("i18n plugin: translations object is empty. At least one locale must be provided.")]
pub struct I18nConfigError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_empty_catalog_error_are_exact() {
        assert_eq!(
            I18nConfig::new(BTreeMap::new()).unwrap_err().to_string(),
            "i18n plugin: translations object is empty. At least one locale must be provided."
        );
        let config = I18nConfig::new(BTreeMap::from([("fr".into(), BTreeMap::new())])).unwrap();
        assert_eq!(config.default_locale, "en");
        assert_eq!(config.detection, [I18nLocaleDetection::Header]);
        assert_eq!(config.locale_cookie, "locale");
        assert_eq!(config.user_locale_field, "locale");
    }
}
