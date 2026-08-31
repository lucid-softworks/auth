use phonenumber::{Mode, Type, country, metadata::DATABASE};

const INVALID_PHONE_NUMBERS: &[&str] = &[
    "+15550000000",
    "+15550001111",
    "+15550001234",
    "+15551234567",
    "+15555555555",
    "+15551111111",
    "+15550000001",
    "+15550123456",
    "+12125551234",
    "+13105551234",
    "+14155551234",
    "+12025551234",
    "+10000000000",
    "+11111111111",
    "+12222222222",
    "+13333333333",
    "+14444444444",
    "+16666666666",
    "+17777777777",
    "+18888888888",
    "+19999999999",
    "+11234567890",
    "+10123456789",
    "+19876543210",
    "+441632960000",
    "+447700900000",
    "+447700900001",
    "+447700900123",
    "+447700900999",
    "+442079460000",
    "+442079460123",
    "+441134960000",
    "+0000000000",
    "+1000000000",
    "+123456789",
    "+1234567890",
    "+12345678901",
    "+0123456789",
    "+9876543210",
    "+99999999999",
    "+491234567890",
    "+491111111111",
    "+33123456789",
    "+33111111111",
    "+61123456789",
    "+61111111111",
    "+81123456789",
    "+81111111111",
    "+19001234567",
    "+19761234567",
    "+1911",
    "+1411",
    "+1611",
    "+44999",
    "+44112",
];

const EMBEDDED_SEQUENCES: &[&str] = &[
    "1234567890",
    "0123456789",
    "9876543210",
    "0987654321",
    "12121212",
    "21212121",
    "00000000",
    "147258369",
    "258369147",
    "369258147",
    "789456123",
    "123456789",
    "1234512345",
    "1111122222",
    "1212121212",
    "1010101010",
];

/// Validate a phone number using the pinned Sentinel defaults.
pub fn is_valid_phone(phone: &str) -> bool {
    let Ok(number) = phonenumber::parse(None, phone) else {
        return false;
    };
    if !number.is_valid() || number.number_type(&DATABASE) == Type::PremiumRate {
        return false;
    }
    let e164 = number.format().mode(Mode::E164).to_string();
    let national = number.national().to_string();
    !is_fake_phone_number(&e164, &national, number.country().id())
}

fn is_fake_phone_number(
    e164: &str,
    national: &str,
    country_id: Option<country::Id>,
) -> bool {
    if INVALID_PHONE_NUMBERS.contains(&e164) || matches_fake_pattern(e164) {
        return true;
    }
    let invalid_prefixes: &[&str] = match country_id {
        Some(country::US) => &["555", "000", "111", "911", "411", "611"],
        Some(country::CA) => &["555", "000", "911"],
        Some(country::GB) => &["7700900", "1632960", "1134960"],
        Some(country::AU) => &["0491570", "0491571", "0491572"],
        _ => &[],
    };
    invalid_prefixes
        .iter()
        .any(|prefix| national.starts_with(prefix))
        || all_digits_equal(national)
        || digits_are_sequential(national)
}

fn matches_fake_pattern(e164: &str) -> bool {
    let Some(digits) = e164.strip_prefix('+') else {
        return false;
    };
    (digits.len() >= 8 && all_digits_equal(&digits[1..]))
        || EMBEDDED_SEQUENCES
            .iter()
            .any(|sequence| digits.contains(sequence))
        || (digits.starts_with('1')
            && digits.len() == 11
            && digits.get(4..7) == Some("555"))
        || (2..=8).contains(&digits.len())
        || (digits.len() >= 8
            && digits.ends_with("0000000")
            && digits[..digits.len() - 7].chars().all(|digit| digit.is_ascii_digit()))
}

fn all_digits_equal(digits: &str) -> bool {
    let mut digits = digits.bytes();
    let Some(first) = digits.next() else {
        return false;
    };
    digits.all(|digit| digit == first)
}

fn digits_are_sequential(digits: &str) -> bool {
    digits.len() >= 6
        && digits
            .as_bytes()
            .windows(2)
            .all(|pair| pair[0].abs_diff(pair[1]) == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_realistic_numbers_and_blocks_published_fakes() {
        assert!(is_valid_phone("+1 520-878-2491"));
        assert!(is_valid_phone("+44 20 7946 0958"));
        assert!(!is_valid_phone("+1 415-555-1234"));
        assert!(!is_valid_phone("+44 7700 900123"));
        assert!(!is_valid_phone("+12345678901"));
        assert!(!is_valid_phone("not-a-phone"));
    }
}
