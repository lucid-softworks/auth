use super::{
    callback::CallbackLedger, database::StrategyDatabase, oauth_provider_fixtures as fixture,
};
use lucid_auth::{
    DatabaseIdGenerationSize, DatabaseIdInput, DatabaseIdPlan, OAuthClientRegistrationMode,
    OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite, OAuthClientResourceLinkOutcome,
    OAuthProviderAssertionStore, OAuthProviderClientStore, OAuthProviderConsentStore,
    OAuthProviderResourceStore, OAuthProviderTokenStore, OAuthTokenIssuance,
    postgres::PostgresOAuthProviderStore,
};

pub(super) const MODELS: [&str; 7] = [
    "oauthResource",
    "oauthClient",
    "oauthClientResource",
    "oauthConsent",
    "oauthRefreshToken",
    "oauthAccessToken",
    "oauthClientAssertion",
];

pub(super) struct OAuthIds {
    pub(super) resource: String,
    pub(super) client: String,
    pub(super) client_resource: String,
    pub(super) consent: String,
    pub(super) refresh: String,
    pub(super) access: String,
    pub(super) assertion: String,
}

pub(super) async fn exercise(
    database: &StrategyDatabase,
    label: &str,
    user_id: &str,
    session_id: &str,
    ledger: Option<&CallbackLedger>,
    physical_type: &str,
) -> Result<OAuthIds, Box<dyn std::error::Error>> {
    let store = PostgresOAuthProviderStore::new((*database.store).clone());
    let resource_input = fixture::resource(label);
    let resource_identifier = resource_input.identifier.clone();
    let resource_plan = plan(database, MODELS[0]);
    let resource = store
        .create_oauth_resource(
            &|| resource_plan.prepare(database.store.as_ref()),
            resource_input,
        )
        .await?
        .expect("new OAuth resource");

    let client_input = fixture::client(label, user_id);
    let client_id = client_input.client_id.clone();
    let client_plan = plan(database, MODELS[1]);
    let link_plan = plan(database, MODELS[2]);
    let registration = store
        .persist_oauth_client_registration(
            &|| client_plan.prepare(database.store.as_ref()),
            &|| link_plan.prepare(database.store.as_ref()),
            OAuthClientRegistrationWrite {
                client: client_input,
                resource_ids: vec![resource_identifier.clone()],
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await?;
    let OAuthClientRegistrationOutcome::Created(client) = registration else {
        panic!("expected a new OAuth client: {registration:?}");
    };
    let link = store
        .list_oauth_client_resources(&client_id)
        .await?
        .remove(0);

    let consent_plan = plan(database, MODELS[3]);
    let consent = store
        .upsert_oauth_consent(
            &|| consent_plan.prepare(database.store.as_ref()),
            fixture::consent(label, &client_id, user_id),
        )
        .await?;
    let tokens = create_token_ids(database, &store, label, &client_id, user_id, session_id).await?;
    let ids = OAuthIds {
        resource: resource.id,
        client: client.id,
        client_resource: link.id,
        consent: consent.id,
        refresh: tokens.refresh,
        access: tokens.access,
        assertion: tokens.assertion,
    };
    assert_values_and_references(
        database,
        &store,
        OAuthReferences {
            label,
            user_id,
            session_id,
            client_id: &client_id,
            resource_id: &resource_identifier,
        },
        &ids,
    )
    .await?;
    assert_physical_types(database, physical_type).await?;
    if let Some(ledger) = ledger {
        assert_callback_contract(ledger, &ids);
        assert_lazy_conflicts(&store, label, user_id, session_id, ledger).await?;
    }
    Ok(ids)
}

struct TokenIds {
    refresh: String,
    access: String,
    assertion: String,
}

async fn create_token_ids(
    database: &StrategyDatabase,
    store: &PostgresOAuthProviderStore,
    label: &str,
    client_id: &str,
    user_id: &str,
    session_id: &str,
) -> Result<TokenIds, Box<dyn std::error::Error>> {
    let refresh_input = fixture::refresh_token(label, client_id, user_id, session_id);
    let access_input = fixture::access_token(label, client_id, user_id, session_id);
    let refresh_token = refresh_input.token.clone();
    let access_token = access_input.token.clone();
    let refresh_plan = plan(database, MODELS[4]);
    let access_plan = plan(database, MODELS[5]);
    store
        .issue_oauth_tokens(
            &|| refresh_plan.prepare(database.store.as_ref()),
            &|| access_plan.prepare(database.store.as_ref()),
            OAuthTokenIssuance {
                refresh_token: Some(refresh_input),
                access_token: Some(access_input),
            },
        )
        .await?;
    let refresh = store
        .find_oauth_refresh_token(&refresh_token)
        .await?
        .expect("stored refresh token");
    let access = store
        .find_oauth_access_token(&access_token)
        .await?
        .expect("stored access token");

    let assertion = fixture::assertion(label);
    let assertion_jti = assertion.jti.clone();
    let assertion_plan = plan(database, MODELS[6]);
    assert!(
        store
            .reserve_oauth_client_assertion(
                &|| assertion_plan.prepare(database.store.as_ref()),
                assertion,
            )
            .await?
    );
    let assertion_id = sqlx::query_scalar::<_, String>(
        r#"SELECT id::text FROM "oauthClientAssertion" WHERE jti = $1"#,
    )
    .bind(&assertion_jti)
    .fetch_one(&database.pool)
    .await?;
    Ok(TokenIds {
        refresh: refresh.id,
        access: access.id,
        assertion: assertion_id,
    })
}

fn plan(database: &StrategyDatabase, model: &str) -> DatabaseIdPlan {
    DatabaseIdPlan::new(
        database.strategy.clone(),
        model,
        DatabaseIdInput::Absent,
        false,
    )
}

fn assert_callback_contract(ledger: &CallbackLedger, ids: &OAuthIds) {
    let calls = ledger
        .snapshot()
        .into_iter()
        .enumerate()
        .filter(|(_, call)| MODELS.contains(&call.model.as_str()))
        .map(|(index, call)| {
            assert_eq!(call.size, DatabaseIdGenerationSize::Omitted);
            (
                call.model.clone(),
                format!("callback/{}/{}", call.model, index + 1),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        MODELS
    );
    assert_eq!(
        calls.iter().map(|call| call.1.as_str()).collect::<Vec<_>>(),
        ids.all()
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

async fn assert_lazy_conflicts(
    store: &PostgresOAuthProviderStore,
    label: &str,
    user_id: &str,
    session_id: &str,
    ledger: &CallbackLedger,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = ledger.snapshot();
    let unexpected = || -> Result<lucid_auth::PreparedDatabaseId, lucid_auth::AuthError> {
        panic!("a conflicting OAuth write must not prepare an ID")
    };
    assert!(
        store
            .create_oauth_resource(&unexpected, fixture::resource(label))
            .await?
            .is_none()
    );
    let client = fixture::client(label, user_id);
    assert!(matches!(
        store
            .persist_oauth_client_registration(
                &unexpected,
                &unexpected,
                OAuthClientRegistrationWrite {
                    client: client.clone(),
                    resource_ids: vec![fixture::resource(label).identifier],
                    mode: OAuthClientRegistrationMode::Create,
                },
            )
            .await?,
        OAuthClientRegistrationOutcome::ClientIdTaken
    ));
    let link = store
        .list_oauth_client_resources(&client.client_id)
        .await?
        .remove(0);
    assert!(matches!(
        store.link_oauth_client_resource(&unexpected, link).await?,
        OAuthClientResourceLinkOutcome::AlreadyLinked(_)
    ));
    let mut consent = store.list_oauth_consents(user_id).await?.remove(0);
    consent.updated_at = chrono::Utc::now();
    store.upsert_oauth_consent(&unexpected, consent).await?;
    assert!(
        store
            .issue_oauth_tokens(
                &unexpected,
                &unexpected,
                OAuthTokenIssuance {
                    refresh_token: Some(fixture::refresh_token(
                        label,
                        &client.client_id,
                        user_id,
                        session_id,
                    )),
                    access_token: Some(fixture::access_token(
                        label,
                        &client.client_id,
                        user_id,
                        session_id,
                    )),
                },
            )
            .await
            .is_err()
    );
    assert!(
        !store
            .reserve_oauth_client_assertion(&unexpected, fixture::assertion(label))
            .await?
    );
    assert_eq!(ledger.snapshot(), before);
    Ok(())
}

struct OAuthReferences<'a> {
    label: &'a str,
    user_id: &'a str,
    session_id: &'a str,
    client_id: &'a str,
    resource_id: &'a str,
}

async fn assert_values_and_references(
    database: &StrategyDatabase,
    store: &PostgresOAuthProviderStore,
    references: OAuthReferences<'_>,
    ids: &OAuthIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = store
        .find_oauth_client(references.client_id)
        .await?
        .unwrap();
    assert_eq!(client.id, ids.client);
    assert_eq!(client.user_id.as_deref(), Some(references.user_id));
    let link = store
        .list_oauth_client_resources(references.client_id)
        .await?
        .remove(0);
    assert_eq!(link.id, ids.client_resource);
    assert_eq!(link.client_id, references.client_id);
    assert_eq!(link.resource_id, references.resource_id);
    let consent = store
        .list_oauth_consents(references.user_id)
        .await?
        .remove(0);
    assert_eq!(consent.id, ids.consent);
    assert_eq!(consent.client_id, references.client_id);
    assert_eq!(consent.user_id.as_deref(), Some(references.user_id));
    let refresh = store
        .find_oauth_refresh_token(&format!("strategy-{}-refresh", references.label))
        .await?
        .unwrap();
    let access = store
        .find_oauth_access_token(&format!("strategy-{}-access", references.label))
        .await?
        .unwrap();
    assert_eq!(refresh.client_id, references.client_id);
    assert_eq!(refresh.user_id, references.user_id);
    assert_eq!(refresh.session_id.as_deref(), Some(references.session_id));
    assert_eq!(access.client_id, references.client_id);
    assert_eq!(access.user_id.as_deref(), Some(references.user_id));
    assert_eq!(access.session_id.as_deref(), Some(references.session_id));
    assert_eq!(access.refresh_id.as_deref(), Some(ids.refresh.as_str()));
    assert_eq!(
        store
            .find_oauth_resource(references.resource_id)
            .await?
            .unwrap()
            .id,
        ids.resource
    );
    let assertion = sqlx::query_scalar::<_, String>(
        r#"SELECT jti FROM "oauthClientAssertion" WHERE id::text = $1"#,
    )
    .bind(&ids.assertion)
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(
        assertion,
        format!("strategy-{}-assertion", references.label)
    );
    Ok(())
}

async fn assert_physical_types(
    database: &StrategyDatabase,
    primary: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for table in MODELS {
        assert_column_type(database, table, "id", primary).await?;
    }
    for (table, column, expected) in [
        ("oauthClient", "userId", primary),
        ("oauthClientResource", "clientId", "text"),
        ("oauthClientResource", "resourceId", "text"),
        ("oauthRefreshToken", "clientId", "text"),
        ("oauthRefreshToken", "sessionId", primary),
        ("oauthRefreshToken", "userId", primary),
        ("oauthAccessToken", "clientId", "text"),
        ("oauthAccessToken", "sessionId", primary),
        ("oauthAccessToken", "userId", primary),
        ("oauthAccessToken", "refreshId", primary),
        ("oauthConsent", "clientId", "text"),
        ("oauthConsent", "userId", primary),
    ] {
        assert_column_type(database, table, column, expected).await?;
    }
    Ok(())
}

async fn assert_column_type(
    database: &StrategyDatabase,
    table: &str,
    column: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = sqlx::query_scalar::<_, String>(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(actual, expected, "unexpected type for {table}.{column}");
    Ok(())
}

impl OAuthIds {
    pub(super) fn all(&self) -> [&String; 7] {
        [
            &self.resource,
            &self.client,
            &self.client_resource,
            &self.consent,
            &self.refresh,
            &self.access,
            &self.assertion,
        ]
    }
}
