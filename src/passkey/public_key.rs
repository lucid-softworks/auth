use crate::StoredPasskey;
use base64::Engine;
use webauthn_rs_core::proto::{
    AttestationFormat, AuthenticatorTransport, COSEKey, Credential, ParsedAttestation,
    RegisteredExtensions, UserVerificationPolicy,
};

pub(crate) fn credential_from_official_fields(
    stored: &StoredPasskey,
) -> Result<Credential, String> {
    let cred_id = serde_json::from_value(serde_json::Value::String(stored.credential_id.clone()))
        .map_err(|error| format!("credentialID is invalid: {error}"))?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&stored.public_key)
        .map_err(|error| format!("publicKey is invalid base64: {error}"))?;
    let public_key: serde_cbor_2::Value = serde_cbor_2::from_slice(&public_key)
        .map_err(|error| format!("publicKey is invalid COSE CBOR: {error}"))?;
    let cred = COSEKey::try_from(&public_key)
        .map_err(|error| format!("publicKey is invalid COSE key: {error}"))?;
    let transports = stored
        .transports
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split(',')
                .map(|transport| {
                    serde_json::from_value::<AuthenticatorTransport>(serde_json::Value::String(
                        transport.to_owned(),
                    ))
                    .map_err(|error| format!("transport '{transport}' is invalid: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    Ok(Credential {
        cred_id,
        cred,
        counter: stored.counter,
        transports,
        // Better Auth does not persist registration-time UV state and authenticates with
        // `requireUserVerification: false`; treating the unknown state as verified would
        // reject credentials that the official plugin accepts.
        user_verified: false,
        backup_eligible: stored.device_type == "multiDevice",
        backup_state: stored.backed_up,
        registration_policy: UserVerificationPolicy::Preferred,
        extensions: RegisteredExtensions::none(),
        attestation: ParsedAttestation::default(),
        attestation_format: AttestationFormat::None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_cbor_2::Value as CborValue;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[test]
    fn reconstructs_verifier_credential_from_only_official_fields() {
        let key = CborValue::Map(BTreeMap::from([
            (CborValue::Integer(1), CborValue::Integer(2)),
            (CborValue::Integer(3), CborValue::Integer(-7)),
            (CborValue::Integer(-1), CborValue::Integer(1)),
            (
                CborValue::Integer(-2),
                CborValue::Bytes(
                    hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                        .unwrap(),
                ),
            ),
            (
                CborValue::Integer(-3),
                CborValue::Bytes(
                    hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
                        .unwrap(),
                ),
            ),
        ]));
        let stored = StoredPasskey {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: None,
            credential_id: "AQID".into(),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(serde_cbor_2::to_vec(&key).unwrap()),
            counter: 7,
            device_type: "multiDevice".into(),
            backed_up: true,
            transports: Some("usb,internal".into()),
            aaguid: None,
            created_at: Utc::now(),
        };

        let credential = credential_from_official_fields(&stored).unwrap();
        assert_eq!(credential.counter, 7);
        assert!(!credential.user_verified);
        assert!(credential.backup_eligible);
        assert!(credential.backup_state);
        assert_eq!(credential.transports.unwrap().len(), 2);
    }
}
