use percent_encoding::percent_decode_str;

pub(super) fn dub_id(headers: &std::collections::BTreeMap<String, String>) -> Option<String> {
    let header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))?
        .1
        .as_str();
    parse_cookie(header, "dub_id").filter(|value| !value.is_empty())
}

fn parse_cookie(header: &str, expected: &str) -> Option<String> {
    for pair in header.split(';') {
        let Some((name, raw_value)) = pair.split_once('=') else {
            continue;
        };
        if name.trim() != expected {
            continue;
        }
        let value = unquote(raw_value.trim());
        return Some(decode_or_preserve(value));
    }
    None
}

fn unquote(value: &str) -> &str {
    if !value.starts_with('"') {
        return value;
    }
    let without_first = &value[1..];
    without_first
        .char_indices()
        .next_back()
        .map_or("", |(last, _)| &without_first[..last])
}

fn decode_or_preserve(value: &str) -> String {
    if !value.contains('%') || !has_valid_percent_triplets(value) {
        return value.to_owned();
    }
    percent_decode_str(value)
        .decode_utf8()
        .map_or_else(|_| value.to_owned(), |decoded| decoded.into_owned())
}

fn has_valid_percent_triplets(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(pair) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn read(header: &str) -> Option<String> {
        dub_id(&BTreeMap::from([("Cookie".into(), header.into())]))
    }

    #[test]
    fn parser_matches_better_call_cookie_semantics() {
        assert_eq!(read("dub_id=click%20one"), Some("click one".into()));
        assert_eq!(read("dub_id=%ZZ%FF"), Some("%ZZ%FF".into()));
        assert_eq!(read("dub_id=%ZZ%20"), Some("%ZZ%20".into()));
        assert_eq!(read("dub_id=\"quoted%20id\""), Some("quoted id".into()));
        assert_eq!(read("dub_id=first; dub_id=second"), Some("first".into()));
        assert_eq!(read("DUB_ID=wrong; dub_id=right"), Some("right".into()));
        assert_eq!(read("other=value; dub_id=a=b"), Some("a=b".into()));
    }

    #[test]
    fn absent_and_empty_values_are_suppressed() {
        assert_eq!(read("other=value"), None);
        assert_eq!(read("dub_id="), None);
        assert_eq!(read("dub_id=\"\""), None);
    }
}
