use base64::Engine;
use serde_cbor_2::Value as CborValue;
use serde_json::Value;
use std::collections::BTreeMap;
use webauthn_rs_core::proto::{
    COSEAlgorithm, COSEKey, COSEKeyType, Credential, ECDSACurve, EDDSACurve,
};

pub(crate) fn public_key_from_credential_value(value: &Value) -> Result<String, String> {
    let value = if value.get("cred_id").is_some() {
        value.clone()
    } else {
        value.get("cred").cloned().unwrap_or_else(|| value.clone())
    };
    let credential: Credential =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    public_key(&credential.cred)
}

fn public_key(key: &COSEKey) -> Result<String, String> {
    let mut fields = BTreeMap::from([
        (
            CborValue::Integer(1),
            CborValue::Integer(key_type(&key.key)),
        ),
        (
            CborValue::Integer(3),
            CborValue::Integer(algorithm(key.type_)),
        ),
    ]);
    match &key.key {
        COSEKeyType::EC_EC2(key) => {
            fields.insert(
                CborValue::Integer(-1),
                CborValue::Integer(ecdsa_curve(&key.curve)),
            );
            fields.insert(
                CborValue::Integer(-2),
                CborValue::Bytes(key.x.as_slice().to_vec()),
            );
            fields.insert(
                CborValue::Integer(-3),
                CborValue::Bytes(key.y.as_slice().to_vec()),
            );
        }
        COSEKeyType::EC_OKP(key) => {
            fields.insert(
                CborValue::Integer(-1),
                CborValue::Integer(eddsa_curve(&key.curve)),
            );
            fields.insert(
                CborValue::Integer(-2),
                CborValue::Bytes(key.x.as_slice().to_vec()),
            );
        }
        COSEKeyType::RSA(key) => {
            fields.insert(
                CborValue::Integer(-1),
                CborValue::Bytes(key.n.as_slice().to_vec()),
            );
            fields.insert(CborValue::Integer(-2), CborValue::Bytes(key.e.to_vec()));
        }
    }
    serde_cbor_2::to_vec(&CborValue::Map(fields))
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
        .map_err(|error| error.to_string())
}

fn key_type(key: &COSEKeyType) -> i128 {
    match key {
        COSEKeyType::EC_OKP(_) => 1,
        COSEKeyType::EC_EC2(_) => 2,
        COSEKeyType::RSA(_) => 3,
    }
}

fn algorithm(algorithm: COSEAlgorithm) -> i128 {
    match algorithm {
        COSEAlgorithm::ES256 => -7,
        COSEAlgorithm::ES384 => -35,
        COSEAlgorithm::ES512 => -36,
        COSEAlgorithm::RS256 => -257,
        COSEAlgorithm::RS384 => -258,
        COSEAlgorithm::RS512 => -259,
        COSEAlgorithm::PS256 => -37,
        COSEAlgorithm::PS384 => -38,
        COSEAlgorithm::PS512 => -39,
        COSEAlgorithm::EDDSA => -8,
        COSEAlgorithm::INSECURE_RS1 => -65535,
        COSEAlgorithm::PinUvProtocol => -25,
    }
}

fn ecdsa_curve(curve: &ECDSACurve) -> i128 {
    match curve {
        ECDSACurve::SECP256R1 => 1,
        ECDSACurve::SECP384R1 => 2,
        ECDSACurve::SECP521R1 => 3,
    }
}

fn eddsa_curve(curve: &EDDSACurve) -> i128 {
    match curve {
        EDDSACurve::ED25519 => 6,
        EDDSACurve::ED448 => 7,
    }
}
