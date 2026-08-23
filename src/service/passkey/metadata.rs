use crate::AuthError;
use base64::Engine;
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

#[derive(Clone)]
pub(super) struct RegistrationMetadata {
    pub public_key: String,
    pub counter: u32,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
}

pub(super) fn registration_metadata(
    response: &RegisterPublicKeyCredential,
) -> Result<RegistrationMetadata, AuthError> {
    use serde_cbor_2::Value as CborValue;

    let attestation: CborValue = serde_cbor_2::from_slice(&response.response.attestation_object)
        .map_err(|_| AuthError::PasskeyVerificationFailed)?;
    let CborValue::Map(fields) = attestation else {
        return Err(AuthError::PasskeyVerificationFailed);
    };
    let auth_data = fields
        .get(&CborValue::Text("authData".into()))
        .and_then(|value| match value {
            CborValue::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or(AuthError::PasskeyVerificationFailed)?;
    if auth_data.len() < 55 || auth_data[32] & 0x40 == 0 {
        return Err(AuthError::PasskeyVerificationFailed);
    }
    let counter = u32::from_be_bytes(
        auth_data[33..37]
            .try_into()
            .map_err(|_| AuthError::PasskeyVerificationFailed)?,
    );
    let aaguid_bytes: [u8; 16] = auth_data[37..53]
        .try_into()
        .map_err(|_| AuthError::PasskeyVerificationFailed)?;
    let credential_length = usize::from(u16::from_be_bytes(
        auth_data[53..55]
            .try_into()
            .map_err(|_| AuthError::PasskeyVerificationFailed)?,
    ));
    let public_key_start = 55_usize
        .checked_add(credential_length)
        .filter(|start| *start < auth_data.len())
        .ok_or(AuthError::PasskeyVerificationFailed)?;
    let mut deserializer = serde_cbor_2::Deserializer::from_slice(&auth_data[public_key_start..]);
    let _: CborValue = serde::Deserialize::deserialize(&mut deserializer)
        .map_err(|_| AuthError::PasskeyVerificationFailed)?;
    let public_key_end = public_key_start + deserializer.byte_offset();
    let transports = Some(
        response
            .response
            .transports
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| serde_json::to_value(value).ok())
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default(),
    );
    Ok(RegistrationMetadata {
        public_key: base64::engine::general_purpose::STANDARD
            .encode(&auth_data[public_key_start..public_key_end]),
        counter,
        device_type: if auth_data[32] & 0x08 != 0 {
            "multiDevice".into()
        } else {
            "singleDevice".into()
        },
        backed_up: auth_data[32] & 0x10 != 0,
        transports,
        aaguid: Some(Uuid::from_bytes(aaguid_bytes).to_string()),
    })
}
