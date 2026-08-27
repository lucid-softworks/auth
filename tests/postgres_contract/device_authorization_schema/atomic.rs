use super::{fixtures::insert, *};

pub(super) async fn claim_and_consume_are_single_winner(
    store: &PostgresDeviceAuthorizationStore,
    auth_store: &PostgresStore,
    users: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let unclaimed = insert(store, auth_store, code("claim", None)).await?;
    let left_user = users[0].as_str();
    let right_user = users[1].as_str();
    let (left, right) = tokio::join!(
        store.bind_pending_user(&unclaimed.id, left_user),
        store.bind_pending_user(&unclaimed.id, right_user),
    );
    let claims = [left?, right?];
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    let winner = claims
        .into_iter()
        .flatten()
        .next()
        .expect("one atomic claim");
    assert!(
        winner.user_id.as_deref() == Some(left_user)
            || winner.user_id.as_deref() == Some(right_user)
    );

    let mut approved = code("consume", Some(users[2].clone()));
    approved.status = DeviceCodeStatus::Approved;
    let approved = insert(store, auth_store, approved).await?;
    assert!(
        store
            .consume_approved_device_code(
                &approved.id,
                DeviceCodeOwner::OAuthClientId("wrong-client".into()),
            )
            .await?
            .is_none()
    );
    let owner = DeviceCodeOwner::OAuthClientId("oauth-client".into());
    let (left, right) = tokio::join!(
        store.consume_approved_device_code(&approved.id, owner.clone()),
        store.consume_approved_device_code(&approved.id, owner),
    );
    let consumed = [left?, right?];
    assert_eq!(consumed.iter().filter(|code| code.is_some()).count(), 1);
    assert!(
        store
            .find_device_code(&approved.device_code)
            .await?
            .is_none()
    );
    Ok(())
}
