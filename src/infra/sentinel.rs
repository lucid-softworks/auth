//! Sentinel security primitives matching `@better-auth/infra@0.4.3`.
//!
//! The public proof-of-work helpers are native, in-process equivalents of the
//! package's root exports. Server, browser, and native client compatibility
//! build on this module without spawning a JavaScript runtime.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Published default proof-of-work difficulty in leading zero bits.
pub const DEFAULT_DIFFICULTY: u32 = 18;
/// Published proof-of-work challenge lifetime in seconds.
pub const CHALLENGE_TTL: u64 = 60;

/// Challenge returned by the Infra security service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoWChallenge {
    pub nonce: String,
    pub difficulty: u32,
    pub timestamp: u64,
    pub ttl: u64,
}

/// Counter that satisfies a proof-of-work challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoWSolution {
    pub nonce: String,
    pub counter: u64,
}

/// Find the first counter whose SHA-256 digest has the requested zero prefix.
pub async fn solve_pow_challenge(challenge: &PoWChallenge) -> PoWSolution {
    let mut counter = 0_u64;
    loop {
        if verify_pow_solution(&challenge.nonce, counter, challenge.difficulty) {
            return PoWSolution {
                nonce: challenge.nonce.clone(),
                counter,
            };
        }
        counter = counter.saturating_add(1);
        if counter % 1_000 == 0 {
            tokio::task::yield_now().await;
        }
    }
}

/// Decode the package's base64-encoded JSON challenge representation.
pub fn decode_pow_challenge(encoded: &str) -> Option<PoWChallenge> {
    STANDARD
        .decode(encoded)
        .ok()
        .and_then(|decoded| serde_json::from_slice(&decoded).ok())
}

/// Encode a solution as base64 JSON with the published field order.
pub fn encode_pow_solution(solution: &PoWSolution) -> String {
    let encoded = serde_json::to_vec(solution).expect("proof-of-work solution is serializable");
    STANDARD.encode(encoded)
}

/// Verify a proof-of-work solution locally.
pub fn verify_pow_solution(nonce: &str, counter: u64, difficulty: u32) -> bool {
    let digest = Sha256::digest(format!("{nonce}:{counter}").as_bytes());
    has_leading_zero_bits(&digest, difficulty)
}

fn has_leading_zero_bits(digest: &[u8], bits: u32) -> bool {
    if bits > (digest.len() as u32) * 8 {
        return false;
    }
    let full_bytes = (bits / 8) as usize;
    let remaining_bits = bits % 8;
    if digest[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    remaining_bits == 0
        || digest
            .get(full_bytes)
            .is_some_and(|byte| byte >> (8 - remaining_bits) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_published_constants() {
        assert_eq!(DEFAULT_DIFFICULTY, 18);
        assert_eq!(CHALLENGE_TTL, 60);
    }

    #[test]
    fn decodes_the_published_base64_json_shape() {
        assert_eq!(
            decode_pow_challenge(
                "eyJub25jZSI6ImFiYyIsImRpZmZpY3VsdHkiOjgsInRpbWVzdGFtcCI6MTIzLCJ0dGwiOjYwfQ=="
            ),
            Some(PoWChallenge {
                nonce: "abc".into(),
                difficulty: 8,
                timestamp: 123,
                ttl: 60,
            })
        );
        assert_eq!(decode_pow_challenge("not base64"), None);
    }

    #[test]
    fn encodes_the_published_solution_shape() {
        assert_eq!(
            encode_pow_solution(&PoWSolution {
                nonce: "abc".into(),
                counter: 42,
            }),
            "eyJub25jZSI6ImFiYyIsImNvdW50ZXIiOjQyfQ=="
        );
    }

    #[tokio::test]
    async fn solves_and_verifies_the_first_valid_counter() {
        let challenge = PoWChallenge {
            nonce: "sentinel-contract".into(),
            difficulty: 12,
            timestamp: 0,
            ttl: CHALLENGE_TTL,
        };
        let solution = solve_pow_challenge(&challenge).await;

        assert!(verify_pow_solution(
            &solution.nonce,
            solution.counter,
            challenge.difficulty
        ));
        assert!((0..solution.counter).all(|counter| {
            !verify_pow_solution(&solution.nonce, counter, challenge.difficulty)
        }));
        assert!(!verify_pow_solution(&solution.nonce, solution.counter, 257));
    }
}
