#[derive(Serialize, Deserialize)]
struct RotationReplayEnvelope {
    fingerprint: String,
    response: Value,
}

fn replay_response(
    service: &AuthService,
    refresh: &OAuthProviderRefreshToken,
    fingerprint: &str,
) -> Result<Option<Value>, OAuthProviderError> {
    let Some(encrypted) = refresh.rotation_replay_response.as_deref() else {
        return Ok(None);
    };
    let decrypted = service
        .decrypt_oauth_provider_secret(encrypted)
        .map_err(|_| OAuthProviderError::InvalidGrant("invalid refresh token".into()))?;
    let envelope: RotationReplayEnvelope = serde_json::from_slice(&decrypted)
        .map_err(|_| OAuthProviderError::InvalidGrant("invalid refresh token".into()))?;
    if envelope.fingerprint != fingerprint {
        return Ok(None);
    }
    let mut response = envelope.response;
    if let Some(object) = response.as_object_mut()
        && let Some(expires_at) = object.get("expires_at").and_then(Value::as_i64)
    {
        object.insert(
            "expires_in".into(),
            Value::from((expires_at - Utc::now().timestamp()).max(0)),
        );
    }
    Ok(Some(response))
}

fn rotation_request_fingerprint(
    client_id: &str,
    scopes: &[String],
    resources: Option<&[String]>,
    confirmation: Option<&Value>,
) -> String {
    let mut scopes = scopes.to_vec();
    scopes.sort();
    scopes.dedup();
    let mut resources = resources.unwrap_or_default().to_vec();
    resources.sort();
    resources.dedup();
    hash_token(&json!({
        "clientId": client_id,
        "scopes": scopes,
        "resources": resources,
        "confirmation": confirmation,
    }).to_string())
}

#[derive(Clone, Copy)]
struct DpopContext<'a> {
    service: &'a AuthService,
    config: &'a OAuthProviderConfig,
    store: &'a dyn OAuthProviderStore,
}

impl<'a> DpopContext<'a> {
    fn new(
        service: &'a AuthService,
        config: &'a OAuthProviderConfig,
        store: &'a dyn OAuthProviderStore,
    ) -> Self {
        Self {
            service,
            config,
            store,
        }
    }
}

async fn dpop_for_token_endpoint(
    context: DpopContext<'_>,
    client: &OAuthProviderClient,
    policy: &ResourcePolicy,
    expected_jkt: Option<&str>,
    headers: &HeaderMap,
    endpoint: &str,
) -> Result<Option<String>, OAuthProviderError> {
    let proof = headers.get("dpop").and_then(|value| value.to_str().ok());
    let required =
        client.dpop_bound_access_tokens || policy.dpop_required || expected_jkt.is_some();
    match proof {
        Some(proof) => verify_dpop(context, proof, "POST", endpoint, expected_jkt, None)
            .await
            .map(Some),
        None if required => Err(OAuthProviderError::InvalidDpopProof(
            "DPoP proof header is required".into(),
        )),
        None => Ok(None),
    }
}

async fn verify_dpop(
    context: DpopContext<'_>,
    proof: &str,
    method: &str,
    endpoint: &str,
    expected_jkt: Option<&str>,
    access_token: Option<&str>,
) -> Result<String, OAuthProviderError> {
    let (header, jwk, key) = dpop_verification_material(context.config, proof)?;
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims.clear();
    let claims = decode::<Value>(proof, &key, &validation)
        .ok()
        .and_then(|decoded| decoded.claims.as_object().cloned())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("invalid DPoP signature".into()))?;
    validate_dpop_claims(context.config, &claims, method, endpoint, access_token)?;
    let jkt = jwk_thumbprint(&jwk)?;
    if expected_jkt.is_some_and(|expected| expected != jkt) {
        return Err(OAuthProviderError::InvalidDpopProof("DPoP key thumbprint mismatch".into()));
    }
    reserve_dpop_proof(
        context.service,
        context.config,
        context.store,
        &jkt,
        &claims,
    )
    .await?;
    Ok(jkt)
}

fn dpop_verification_material(
    config: &OAuthProviderConfig,
    proof: &str,
) -> Result<(Header, jsonwebtoken::jwk::Jwk, DecodingKey), OAuthProviderError> {
    if proof.split('.').count() != 3 {
        return Err(OAuthProviderError::InvalidDpopProof("DPoP proof must be a compact JWT".into()));
    }
    reject_private_dpop_jwk(proof)?;
    let header = decode_header(proof)
        .map_err(|_| OAuthProviderError::InvalidDpopProof("invalid DPoP proof".into()))?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(OAuthProviderError::InvalidDpopProof(
            "DPoP typ must be dpop+jwt".into(),
        ));
    }
    let algorithm = algorithm_name(header.alg);
    if matches!(header.alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
        return Err(OAuthProviderError::InvalidDpopProof("DPoP proof must use an asymmetric JWS algorithm".into()));
    }
    if !config
        .dpop
        .signing_algorithms
        .iter()
        .any(|allowed| allowed == algorithm)
    {
        return Err(OAuthProviderError::InvalidDpopProof(
            "unsupported DPoP signing algorithm".into(),
        ));
    }
    let jwk = header.jwk.clone().ok_or_else(|| {
        OAuthProviderError::InvalidDpopProof("DPoP proof must contain a JWK".into())
    })?;
    let key = DecodingKey::from_jwk(&jwk)
        .map_err(|_| OAuthProviderError::InvalidDpopProof("invalid DPoP JWK".into()))?;
    Ok((header, jwk, key))
}

fn reject_private_dpop_jwk(proof: &str) -> Result<(), OAuthProviderError> {
    let encoded = proof.split('.').next().unwrap_or_default();
    let header: Value = URL_SAFE_NO_PAD.decode(encoded).ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP proof header is invalid".into()))?;
    let jwk = header.get("jwk").and_then(Value::as_object)
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP proof must contain a JWK".into()))?;
    if jwk.get("kty").and_then(Value::as_str) == Some("oct")
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].iter().any(|field| jwk.contains_key(*field))
    {
        return Err(OAuthProviderError::InvalidDpopProof("DPoP proof JWK must be asymmetric public key material".into()));
    }
    Ok(())
}

fn validate_dpop_claims(
    config: &OAuthProviderConfig,
    claims: &Map<String, Value>,
    method: &str,
    endpoint: &str,
    access_token: Option<&str>,
) -> Result<(), OAuthProviderError> {
    let htm = claims.get("htm").and_then(Value::as_str).filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP htm is required".into()))?;
    let htu = claims.get("htu").and_then(Value::as_str).filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP htu is required".into()))?;
    if !htm.eq_ignore_ascii_case(method) || normalize_dpop_htu(htu)? != normalize_dpop_htu(endpoint)? {
        return Err(OAuthProviderError::InvalidDpopProof(
            "DPoP htm or htu mismatch".into(),
        ));
    }
    let now = Utc::now().timestamp();
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP iat is required".into()))?;
    if iat > now + 5 || now - iat > config.dpop.proof_max_age_seconds as i64 {
        return Err(OAuthProviderError::InvalidDpopProof(
            "DPoP proof is outside the accepted age".into(),
        ));
    }
    let _jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP jti is required".into()))?;
    if _jti.len() > 512 {
        return Err(OAuthProviderError::InvalidDpopProof("DPoP jti is too large".into()));
    }
    if let Some(access_token) = access_token {
        let expected_ath = hash_token(access_token);
        if claims.get("ath").and_then(Value::as_str) != Some(expected_ath.as_str()) {
            return Err(OAuthProviderError::InvalidDpopProof(
                "DPoP ath mismatch".into(),
            ));
        }
    }
    Ok(())
}

fn normalize_dpop_htu(value: &str) -> Result<String, OAuthProviderError> {
    let url = Url::parse(value).map_err(|_| OAuthProviderError::InvalidDpopProof("DPoP htu is invalid".into()))?;
    if url.fragment().is_some() {
        return Err(OAuthProviderError::InvalidDpopProof("DPoP htu must not contain a fragment".into()));
    }
    Ok(format!("{}{}", url.origin().ascii_serialization(), url.path()))
}

async fn reserve_dpop_proof(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    jkt: &str,
    claims: &Map<String, Value>,
) -> Result<(), OAuthProviderError> {
    let jti = claims.get("jti").and_then(Value::as_str)
        .expect("validated DPoP jti");
    let htm = claims.get("htm").and_then(Value::as_str).expect("validated DPoP htm").to_ascii_uppercase();
    let htu = normalize_dpop_htu(claims.get("htu").and_then(Value::as_str).expect("validated DPoP htu"))?;
    let replay_id = hash_token(&format!("{jkt}\n{htm}\n{htu}\n{jti}"));
    let iat = claims.get("iat").and_then(Value::as_i64).expect("validated DPoP iat");
    let expires_at = DateTime::from_timestamp(iat + config.dpop.proof_max_age_seconds as i64, 0)
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP iat is invalid".into()))?;
    let reserved = store
        .reserve_oauth_client_assertion(
            &|| service.prepare_database_id(&service.database_id_plan(
                "oauthClientAssertion", crate::DatabaseIdInput::Absent, false,
            )),
            OAuthProviderClientAssertion {
                id: String::new(),
                jti: replay_id,
                expires_at,
            },
        )
        .await
        .map_err(server)?;
    if !reserved {
        return Err(OAuthProviderError::InvalidDpopProof(
            "DPoP proof was already used".into(),
        ));
    }
    Ok(())
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::EdDSA => "EdDSA",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
    }
}

fn jwk_thumbprint(jwk: &jsonwebtoken::jwk::Jwk) -> Result<String, OAuthProviderError> {
    let value = serde_json::to_value(jwk).map_err(json_server)?;
    let object = value
        .as_object()
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("invalid DPoP JWK".into()))?;
    let field = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| OAuthProviderError::InvalidDpopProof("invalid DPoP JWK".into()))
    };
    let canonical = match field("kty")? {
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            field("e")?,
            field("n")?
        ),
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            field("crv")?,
            field("x")?,
            field("y")?
        ),
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            field("crv")?,
            field("x")?
        ),
        _ => {
            return Err(OAuthProviderError::InvalidDpopProof(
                "unsupported DPoP JWK type".into(),
            ));
        }
    };
    Ok(hash_token(&canonical))
}

#[cfg(test)]
mod dpop_tests {
    use super::*;

    fn valid_claims(token: &str) -> Map<String, Value> {
        Map::from_iter([
            ("htm".into(), json!("POST")),
            ("htu".into(), json!("https://issuer.example/oauth2/token")),
            ("iat".into(), json!(Utc::now().timestamp())),
            ("jti".into(), json!("proof-id")),
            ("ath".into(), json!(hash_token(token))),
        ])
    }

    #[test]
    fn proof_claims_enforce_method_uri_age_and_access_token_binding() {
        let config = OAuthProviderConfig::new("/login", "/consent");
        let token = "access-token";
        let claims = valid_claims(token);
        assert!(validate_dpop_claims(&config, &claims, "POST", "https://issuer.example/oauth2/token", Some(token)).is_ok());
        assert!(validate_dpop_claims(&config, &claims, "GET", "https://issuer.example/oauth2/token", Some(token)).is_err());
        assert!(validate_dpop_claims(&config, &claims, "POST", "https://wrong.example", Some(token)).is_err());
        assert!(validate_dpop_claims(&config, &claims, "POST", "https://issuer.example/oauth2/token", Some("other")).is_err());
        let mut stale = claims;
        stale.insert("iat".into(), json!(Utc::now().timestamp() - 301));
        assert!(validate_dpop_claims(&config, &stale, "POST", "https://issuer.example/oauth2/token", Some(token)).is_err());
    }

    #[tokio::test]
    async fn proof_jti_is_single_use_and_thumbprints_are_stable() {
        let config = OAuthProviderConfig::new("/login", "/consent");
        let store = crate::MemoryOAuthProviderStore::new();
        let service = crate::AuthService::try_new(
            std::sync::Arc::new(crate::MemoryStore::default()),
            crate::AuthConfig::new([11_u8; 32]).unwrap(),
        )
        .unwrap();
        let claims = valid_claims("access-token");
        assert!(reserve_dpop_proof(&service, &config, &store, "thumbprint", &claims).await.is_ok());
        assert!(reserve_dpop_proof(&service, &config, &store, "thumbprint", &claims).await.is_err());
        let jwk = serde_json::from_value(json!({"kty":"RSA","e":"AQAB","n":"sXch"})).unwrap();
        assert_eq!(jwk_thumbprint(&jwk).unwrap(), jwk_thumbprint(&jwk).unwrap());
    }
}
