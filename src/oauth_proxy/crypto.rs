use super::{OAuthProxySecret, OAuthProxyVersionedSecret};

pub(crate) fn encrypt(secret: &OAuthProxySecret, plaintext: &[u8]) -> Result<String, ()> {
    match secret {
        OAuthProxySecret::Plain(secret) => crate::symmetric_crypto::encrypt(secret, plaintext),
        OAuthProxySecret::Versioned(secret) => {
            let (current, versions) = versioned_keys(secret)?;
            crate::symmetric_crypto::encrypt_versioned(&current, &versions, plaintext)
        }
    }
}

pub(crate) fn decrypt(secret: &OAuthProxySecret, ciphertext: &str) -> Result<Vec<u8>, ()> {
    match secret {
        OAuthProxySecret::Plain(secret) => crate::symmetric_crypto::decrypt(secret, ciphertext),
        OAuthProxySecret::Versioned(secret) => {
            let (current, versions) = versioned_keys(secret)?;
            crate::symmetric_crypto::decrypt_versioned(
                &current,
                &versions,
                secret.legacy_secret.as_deref(),
                ciphertext,
            )
        }
    }
}

fn versioned_keys(
    secret: &OAuthProxyVersionedSecret,
) -> Result<(Vec<u8>, Vec<crate::VersionedSecret>), ()> {
    let current = secret
        .keys
        .get(&secret.current_version)
        .cloned()
        .ok_or(())?;
    let mut keys = Vec::with_capacity(secret.keys.len());
    keys.push(crate::VersionedSecret {
        version: secret.current_version,
        value: current.clone(),
    });
    keys.extend(
        secret
            .keys
            .iter()
            .filter(|(version, _)| **version != secret.current_version)
            .map(|(version, value)| crate::VersionedSecret {
                version: *version,
                value: value.clone(),
            }),
    );
    Ok((current, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn plain_secret_uses_better_auths_bare_hex_envelope() {
        let secret = OAuthProxySecret::from("compatible-secret");
        let ciphertext = encrypt(&secret, b"oauth-proxy-payload").unwrap();
        assert!(ciphertext.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            decrypt(&secret, &ciphertext).unwrap(),
            b"oauth-proxy-payload"
        );
    }

    #[test]
    fn versioned_secret_uses_current_key_and_reads_retired_and_legacy_payloads() {
        let secret = OAuthProxySecret::Versioned(OAuthProxyVersionedSecret {
            current_version: 7,
            keys: BTreeMap::from([
                (3, b"retired-compatible-secret".to_vec()),
                (7, b"current-compatible-secret".to_vec()),
            ]),
            legacy_secret: Some(b"legacy-compatible-secret".to_vec()),
        });
        let ciphertext = encrypt(&secret, b"current-payload").unwrap();
        assert!(ciphertext.starts_with("$ba$7$"));
        assert_eq!(decrypt(&secret, &ciphertext).unwrap(), b"current-payload");

        let retired =
            crate::symmetric_crypto::encrypt(b"retired-compatible-secret", b"retired-payload")
                .unwrap();
        assert_eq!(
            decrypt(&secret, &format!("$ba$3${retired}")).unwrap(),
            b"retired-payload"
        );

        let legacy =
            crate::symmetric_crypto::encrypt(b"legacy-compatible-secret", b"legacy-payload")
                .unwrap();
        assert_eq!(decrypt(&secret, &legacy).unwrap(), b"legacy-payload");
    }

    #[test]
    fn versioned_secret_requires_its_declared_current_version() {
        let secret = OAuthProxySecret::Versioned(OAuthProxyVersionedSecret {
            current_version: 9,
            keys: BTreeMap::from([(8, b"only-key".to_vec())]),
            legacy_secret: None,
        });
        assert!(encrypt(&secret, b"payload").is_err());
        assert!(decrypt(&secret, "00").is_err());
    }
}
