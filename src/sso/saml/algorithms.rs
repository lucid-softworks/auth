#[derive(Debug, Clone, Copy)]
pub struct SignatureAlgorithm;

impl SignatureAlgorithm {
    pub const RSA_SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    pub const RSA_SHA256: &'static str =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const RSA_SHA384: &'static str =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    pub const RSA_SHA512: &'static str =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    pub const ECDSA_SHA256: &'static str =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    pub const ECDSA_SHA384: &'static str =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    pub const ECDSA_SHA512: &'static str =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
}

#[derive(Debug, Clone, Copy)]
pub struct DigestAlgorithm;

impl DigestAlgorithm {
    pub const SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#sha1";
    pub const SHA256: &'static str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const SHA384: &'static str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    pub const SHA512: &'static str = "http://www.w3.org/2001/04/xmlenc#sha512";
}

#[derive(Debug, Clone, Copy)]
pub struct KeyEncryptionAlgorithm;

impl KeyEncryptionAlgorithm {
    pub const RSA_1_5: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    pub const RSA_OAEP: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    pub const RSA_OAEP_SHA256: &'static str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
}

#[derive(Debug, Clone, Copy)]
pub struct DataEncryptionAlgorithm;

impl DataEncryptionAlgorithm {
    pub const TRIPLEDES_CBC: &'static str =
        "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
    pub const AES_128_CBC: &'static str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    pub const AES_192_CBC: &'static str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
    pub const AES_256_CBC: &'static str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    pub const AES_128_GCM: &'static str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    pub const AES_192_GCM: &'static str = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
    pub const AES_256_GCM: &'static str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
}

pub(super) fn normalize_signature(algorithm: &str) -> &str {
    match algorithm.to_ascii_lowercase().as_str() {
        "sha1" | "rsa-sha1" => SignatureAlgorithm::RSA_SHA1,
        "sha256" | "rsa-sha256" => SignatureAlgorithm::RSA_SHA256,
        "sha384" | "rsa-sha384" => SignatureAlgorithm::RSA_SHA384,
        "sha512" | "rsa-sha512" => SignatureAlgorithm::RSA_SHA512,
        "ecdsa-sha256" => SignatureAlgorithm::ECDSA_SHA256,
        "ecdsa-sha384" => SignatureAlgorithm::ECDSA_SHA384,
        "ecdsa-sha512" => SignatureAlgorithm::ECDSA_SHA512,
        _ => algorithm,
    }
}

pub(super) fn normalize_digest(algorithm: &str) -> &str {
    match algorithm.to_ascii_lowercase().as_str() {
        "sha1" => DigestAlgorithm::SHA1,
        "sha256" => DigestAlgorithm::SHA256,
        "sha384" => DigestAlgorithm::SHA384,
        "sha512" => DigestAlgorithm::SHA512,
        _ => algorithm,
    }
}

pub(super) fn secure_signatures() -> &'static [&'static str] {
    &[
        SignatureAlgorithm::RSA_SHA256,
        SignatureAlgorithm::RSA_SHA384,
        SignatureAlgorithm::RSA_SHA512,
        SignatureAlgorithm::ECDSA_SHA256,
        SignatureAlgorithm::ECDSA_SHA384,
        SignatureAlgorithm::ECDSA_SHA512,
    ]
}

pub(super) fn secure_digests() -> &'static [&'static str] {
    &[
        DigestAlgorithm::SHA256,
        DigestAlgorithm::SHA384,
        DigestAlgorithm::SHA512,
    ]
}
