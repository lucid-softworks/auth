pub(super) fn estimate_entropy(secret: &[u8]) -> f64 {
    let unique = secret
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if unique == 0 {
        return 0.0;
    }
    secret.len() as f64 * (unique as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_javascript_unique_character_estimate() {
        assert_eq!(estimate_entropy(b""), 0.0);
        assert_eq!(estimate_entropy(b"aaaa"), 0.0);
        assert_eq!(estimate_entropy(b"abab"), 4.0);
    }
}
