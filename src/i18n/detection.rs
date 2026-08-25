use super::{I18nConfig, I18nLocaleContext, I18nLocaleDetection};
use percent_encoding::percent_decode_str;
use std::{cmp::Ordering, collections::BTreeMap};

pub(super) async fn detect(config: &I18nConfig, context: I18nLocaleContext) -> String {
    for strategy in &config.detection {
        let locale = match strategy {
            I18nLocaleDetection::Header => context
                .request
                .as_ref()
                .and_then(|request| header(&request.headers, "accept-language"))
                .and_then(|value| {
                    parse_accept_language(value)
                        .into_iter()
                        .find(|locale| config.translations.contains_key(locale))
                }),
            I18nLocaleDetection::Cookie => context
                .request
                .as_ref()
                .and_then(|request| header(&request.headers, "cookie"))
                .and_then(|value| parse_cookies(value).remove(&config.locale_cookie))
                .filter(|locale| config.translations.contains_key(locale)),
            I18nLocaleDetection::Session => context
                .session
                .as_ref()
                .and_then(|session| serde_json::to_value(&session.user).ok())
                .and_then(|user| {
                    user.get(&config.user_locale_field)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .filter(|locale| config.translations.contains_key(locale)),
            I18nLocaleDetection::Callback => match &config.get_locale {
                Some(resolver) => resolver
                    .get_locale(context.clone())
                    .await
                    .filter(|locale| config.translations.contains_key(locale)),
                None => None,
            },
        };
        if let Some(locale) = locale {
            return locale;
        }
    }
    config.default_locale.clone()
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .or_else(|| {
            headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
        .map(String::as_str)
}

fn parse_accept_language(header: &str) -> Vec<String> {
    let mut entries: Vec<_> = header
        .split(',')
        .filter_map(|part| {
            let mut fields = part.trim().split(';');
            let locale = fields.next()?.trim().split('-').next().unwrap_or_default();
            if locale.is_empty() {
                return None;
            }
            let quality = fields.next().unwrap_or("q=1").replacen("q=", "", 1);
            Some((locale.to_owned(), parse_float_prefix(&quality)))
        })
        .collect();
    entries.sort_by(|(_, left), (_, right)| right.partial_cmp(left).unwrap_or(Ordering::Equal));
    entries.into_iter().map(|(locale, _)| locale).collect()
}

fn parse_float_prefix(input: &str) -> f64 {
    let input = input.trim_start();
    if input.starts_with("Infinity") || input.starts_with("+Infinity") {
        return f64::INFINITY;
    }
    if input.starts_with("-Infinity") {
        return f64::NEG_INFINITY;
    }
    let bytes = input.as_bytes();
    let mut end = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let mut digits = 0;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
        digits += 1;
    }
    if bytes.get(end) == Some(&b'.') {
        end += 1;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return f64::NAN;
    }
    let exponent_start = end;
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        end += 1;
        if matches!(bytes.get(end), Some(b'+' | b'-')) {
            end += 1;
        }
        let exponent_digits = end;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == exponent_digits {
            end = exponent_start;
        }
    }
    input[..end].parse().unwrap_or(f64::NAN)
}

fn parse_cookies(header: &str) -> BTreeMap<String, String> {
    let mut cookies = BTreeMap::new();
    if header.len() < 2 {
        return cookies;
    }
    for chunk in header.split(';') {
        let Some(index) = chunk.find('=') else {
            continue;
        };
        let key = trim_ows(&chunk[..index]);
        let value = unquote(trim_ows(&chunk[index + 1..]));
        if valid_cookie_name(key) && valid_cookie_value(value) {
            let decoded = percent_decode_str(value)
                .decode_utf8()
                .map_or_else(|_| value.to_owned(), |value| value.into_owned());
            cookies.insert(key.to_owned(), decoded);
        }
    }
    cookies
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(byte, 0x21 | 0x23..=0x27 | 0x2a..=0x2b | 0x2d..=0x2e | 0x30..=0x39 | 0x41..=0x5a | 0x5e..=0x7a | 0x7c | 0x7e)
        })
}

fn valid_cookie_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parser_matches_quality_base_and_stable_nan_behavior() {
        assert_eq!(
            parse_accept_language("de;q=0.2, fr-CA;q=0.9, es;q=0.4junk"),
            ["fr", "es", "de"]
        );
        assert_eq!(parse_accept_language("en;Q=0.9, fr;q=0.1"), ["en", "fr"]);
        assert_eq!(parse_accept_language("FR-ca, fr-FR;q=0.5"), ["FR", "fr"]);
        assert_eq!(parse_accept_language("en;q=1;ignored=1"), ["en"]);
    }

    #[test]
    fn cookie_parser_is_ows_validated_decoded_and_last_wins() {
        let parsed = parse_cookies(" locale=fr; locale=pt%2DBR; bad name=fr; quoted=\"de\"");
        assert_eq!(parsed.get("locale").map(String::as_str), Some("pt-BR"));
        assert_eq!(parsed.get("quoted").map(String::as_str), Some("de"));
        assert!(!parsed.contains_key("bad name"));
        assert_eq!(
            parse_cookies("x=%ZZ").get("x").map(String::as_str),
            Some("%ZZ")
        );
    }
}
