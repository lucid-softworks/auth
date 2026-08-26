pub(super) fn serial_i32(value: f64) -> Option<i32> {
    (value.is_finite()
        && value.fract() == 0.0
        && value >= f64::from(i32::MIN)
        && value <= f64::from(i32::MAX))
    .then_some(value as i32)
}

pub(super) fn javascript_number(input: &str) -> Option<f64> {
    let input = input.trim();
    if input.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = input.strip_prefix(prefix) {
            return u64::from_str_radix(digits, radix)
                .ok()
                .map(|value| value as f64);
        }
    }
    input.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_javascript_numeric_forms_that_fit_postgres_integer() {
        for (input, expected) in [("42", 42), (" 0x2a ", 42), ("0b101", 5), ("", 0)] {
            assert_eq!(
                javascript_number(input).and_then(serial_i32),
                Some(expected)
            );
        }
    }

    #[test]
    fn rejects_nan_fraction_infinity_and_postgres_integer_overflow() {
        for input in ["not-a-number", "1.5", "Infinity", "2147483648"] {
            assert_eq!(javascript_number(input).and_then(serial_i32), None);
        }
    }
}
