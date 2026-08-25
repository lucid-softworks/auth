use super::{I18nTranslations, TranslationDictionary};
use std::{collections::BTreeMap, sync::OnceLock};

static CATALOGS: OnceLock<I18nTranslations> = OnceLock::new();

pub struct I18nLocales;

impl I18nLocales {
    pub fn all() -> &'static I18nTranslations {
        CATALOGS.get_or_init(|| {
            serde_json::from_str(include_str!("catalogs.json"))
                .expect("the pinned Better Auth i18n catalogs are valid JSON")
        })
    }

    pub fn get(locale: &str) -> Option<&'static TranslationDictionary> {
        Self::all().get(locale)
    }

    pub fn selected(locales: impl IntoIterator<Item = impl AsRef<str>>) -> I18nTranslations {
        locales
            .into_iter()
            .filter_map(|locale| {
                let locale = locale.as_ref().to_owned();
                Self::get(&locale)
                    .cloned()
                    .map(|dictionary| (locale, dictionary))
            })
            .collect::<BTreeMap<_, _>>()
    }
}
