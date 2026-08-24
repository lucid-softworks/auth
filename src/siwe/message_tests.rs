use super::*;

const ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

#[test]
fn parses_only_the_narrow_better_auth_fields() {
    let parsed = parse_siwe_message(&format!(
        "https://Example.COM:443 wants you to sign in with your Ethereum account:\r\n\
         {ADDRESS}\r\n\r\nStatement\r\n\r\n\
         URI: https://example.com/login\r\nVersion: 1\r\nChain ID: 1e2\r\n\
         Nonce: abcDEF12\r\nIssued At: 2026-08-24T12:00:00Z\r\n\
         Expiration Time: 2026-08-24T12:15:00Z\r\n\
         Not Before: 2026-08-24T11:59:00Z\r\nRequest ID: request-1\r\n\
         Resources: ignored"
    ));

    assert_eq!(parsed.scheme.as_deref(), Some("https"));
    assert_eq!(parsed.domain.as_deref(), Some("Example.COM:443"));
    assert_eq!(parsed.address.as_deref(), Some(ADDRESS));
    assert_eq!(parsed.uri.as_deref(), Some("https://example.com/login"));
    assert_eq!(parsed.version.as_deref(), Some("1"));
    assert_eq!(parsed.chain_id, Some(100.0));
    assert_eq!(parsed.nonce.as_deref(), Some("abcDEF12"));
    assert_eq!(parsed.request_id.as_deref(), Some("request-1"));
}

#[test]
fn ignores_malformed_header_address_and_non_integer_chain_id() {
    let parsed = parse_siwe_message(
        "bad domain wants you to sign in with your Ethereum account:\n\
         0X52908400098527886E0F7030069857D2E4169EE7\nChain ID: 1.5",
    );

    assert_eq!(parsed.domain, None);
    assert_eq!(parsed.address, None);
    assert_eq!(parsed.chain_id, None);
}

#[test]
fn later_recognized_fields_replace_earlier_values() {
    let parsed =
        parse_siwe_message("Nonce: first123\nNonce: second45\nChain ID: 0x89\nChain ID: invalid");

    assert_eq!(parsed.nonce.as_deref(), Some("second45"));
    assert_eq!(parsed.chain_id, Some(137.0));
    assert_eq!(parse_siwe_message("Chain ID: 1e20").chain_id, Some(1e20));
}

#[test]
fn normalizes_domains_like_better_auth() {
    assert_eq!(
        normalize_siwe_domain(" HTTPS://Example.COM:443/path?q=1 "),
        "example.com:443"
    );
    assert_eq!(
        normalize_siwe_domain("example.com?query"),
        "example.com?query"
    );
    assert_eq!(normalize_siwe_domain("1://EXAMPLE.COM/path"), "1:");
}

#[test]
fn nonce_requires_eight_to_two_hundred_fifty_ascii_alphanumeric_bytes() {
    assert!(!is_valid_siwe_nonce("1234567"));
    assert!(is_valid_siwe_nonce("abcDEF12"));
    assert!(is_valid_siwe_nonce(&"a".repeat(250)));
    assert!(!is_valid_siwe_nonce(&"a".repeat(251)));
    assert!(!is_valid_siwe_nonce("abcdef_1"));
    assert!(!is_valid_siwe_nonce("é2345678"));
}

#[test]
fn computes_eip_55_checksum_addresses() {
    assert_eq!(
        to_checksum_address(&ADDRESS.to_lowercase()).as_deref(),
        Some(ADDRESS)
    );
    assert_eq!(
        to_checksum_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").as_deref(),
        Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
    );
    assert_eq!(to_checksum_address("not-an-address"), None);
}

#[test]
fn applies_better_auth_time_boundaries_and_ignores_invalid_dates() {
    let boundary = DateTime::parse_from_rfc3339("2026-08-24T12:00:00Z")
        .unwrap()
        .timestamp_millis();
    let mut message = SiweMessage {
        expiration_time: Some("2026-08-24T12:00:00Z".to_owned()),
        ..SiweMessage::default()
    };
    assert_eq!(siwe_time_gate(&message, boundary), SiweTimeGate::Expired);

    message.expiration_time = Some("not-a-date".to_owned());
    message.not_before = Some("2026-08-24T12:00:00Z".to_owned());
    assert_eq!(
        siwe_time_gate(&message, boundary - 1),
        SiweTimeGate::NotYetValid
    );
    assert_eq!(siwe_time_gate(&message, boundary), SiweTimeGate::Valid);

    message.expiration_time = Some("2000-01-01".to_owned());
    message.not_before = None;
    assert_eq!(siwe_time_gate(&message, boundary), SiweTimeGate::Expired);
    assert_v8_expired_forms(&mut message, boundary);

    message.expiration_time = None;
    message.not_before = Some("January 1, 2099".to_owned());
    assert_eq!(
        siwe_time_gate(&message, boundary),
        SiweTimeGate::NotYetValid
    );
    message.not_before = Some("also-not-a-date".to_owned());
    assert_eq!(siwe_time_gate(&message, boundary), SiweTimeGate::Valid);
}

fn assert_v8_expired_forms(message: &mut SiweMessage, boundary: i64) {
    for v8_date in [
        "2000",
        "2000-01",
        "2000-02-30",
        "2000-01-01T00:00",
        "2000-01-01T00:00Z",
        "Aug 24, 2000",
        "24 Aug 2000",
        " 2000-01-01 ",
        "2000-01-01T00:00:00.123456789012345Z",
    ] {
        message.expiration_time = Some(v8_date.to_owned());
        assert_eq!(
            siwe_time_gate(message, boundary),
            SiweTimeGate::Expired,
            "V8-compatible date {v8_date}"
        );
    }
}
