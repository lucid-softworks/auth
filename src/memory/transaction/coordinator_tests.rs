use super::*;
use crate::{
    AuthStore, AuthUser, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    run_database_transaction,
};
use chrono::Utc;
use serde_json::Map;

fn user(email: &str) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: String::new(),
        username: None,
        display_username: None,
        name: "Transaction Test".into(),
        email: email.into(),
        email_verified: false,
        image: None,
        additional_fields: Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

fn create_user(email: &str) -> DatabaseCreateOperation {
    DatabaseCreateOperation::User(DatabaseCreate::new(
        user(email),
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Default,
            "user",
            DatabaseIdInput::Absent,
            true,
        ),
    ))
}

#[tokio::test]
async fn staged_writes_are_visible_to_reentry_and_commit_once() {
    let store = MemoryStore::default();
    let base = store.clone();
    let (user, escaped) = run_database_transaction(&store, move |transaction| {
        Box::pin(async move {
            let DatabaseRecord::User(user) = transaction
                .create(create_user("commit@example.com"))
                .await?
            else {
                unreachable!();
            };
            let committed_id = user.id.clone();
            assert!(
                tokio::spawn(async move { base.find_user_by_id(&committed_id).await })
                    .await
                    .map_err(|error| {
                        AuthError::Storage(format!("visibility task failed: {error}"))
                    })??
                    .is_none()
            );
            assert_eq!(
                transaction
                    .find_by_id(DatabaseModel::User, &user.id)
                    .await?,
                Some(DatabaseRecord::User(user.clone()))
            );
            Ok((user, transaction))
        })
    })
    .await
    .unwrap();

    assert_eq!(store.find_user_by_id(&user.id).await.unwrap(), Some(user));
    assert!(
        escaped
            .find_by_id(DatabaseModel::User, "anything")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn error_rolls_back_the_complete_staged_view() {
    let store = MemoryStore::default();
    let id = Arc::new(std::sync::Mutex::new(None));
    let captured = id.clone();
    let error = run_database_transaction::<(), _>(&store, move |transaction| {
        Box::pin(async move {
            let DatabaseRecord::User(user) = transaction
                .create(create_user("rollback@example.com"))
                .await?
            else {
                unreachable!();
            };
            *captured.lock().unwrap() = Some(user.id);
            Err(AuthError::Storage("cancelled".into()))
        })
    })
    .await
    .unwrap_err();

    assert!(matches!(error, AuthError::Storage(message) if message == "cancelled"));
    let rolled_back_id = id.lock().unwrap().clone().unwrap();
    assert!(
        store
            .find_user_by_id(&rolled_back_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn nested_transactions_reuse_the_active_staged_adapter() {
    let store = MemoryStore::default();
    let nested_store = store.clone();
    let user = run_database_transaction(&store, move |outer| {
        Box::pin(async move {
            let nested_store = nested_store.clone();
            let user = run_database_transaction(&nested_store, move |inner| {
                Box::pin(async move {
                    assert!(Arc::ptr_eq(&outer, &inner));
                    let DatabaseRecord::User(user) =
                        inner.create(create_user("nested@example.com")).await?
                    else {
                        unreachable!();
                    };
                    Ok(user)
                })
            })
            .await?;
            let committed_store = nested_store.clone();
            let committed_id = user.id.clone();
            assert!(
                tokio::spawn(async move {
                    committed_store.find_user_by_id(&committed_id).await
                })
                .await
                .map_err(|error| {
                    AuthError::Storage(format!("visibility task failed: {error}"))
                })??
                .is_none()
            );
            Ok(user)
        })
    })
    .await
    .unwrap();

    assert_eq!(store.find_user_by_id(&user.id).await.unwrap(), Some(user));
}
