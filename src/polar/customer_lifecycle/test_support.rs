use crate::polar::*;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub(super) struct FakePolarClient {
    pub calls: Mutex<Vec<String>>,
    pub customers: Mutex<Vec<PolarCustomer>>,
    pub list_error: Mutex<Option<PolarProviderError>>,
    pub create_error: Mutex<Option<PolarProviderError>>,
    pub update_error: Mutex<Option<PolarProviderError>>,
    pub delete_error: Mutex<Option<PolarProviderError>>,
    pub creates: Mutex<Vec<PolarCustomerCreate>>,
    pub updates: Mutex<Vec<(String, PolarCustomerUpdate)>>,
    pub external_updates: Mutex<Vec<(String, PolarCustomerUpdateExternal)>>,
    pub deletes: Mutex<Vec<String>>,
}

impl FakePolarClient {
    pub fn customer(id: &str, external_id: Option<&str>) -> PolarCustomer {
        PolarCustomer {
            id: id.to_owned(),
            external_id: external_id.map(str::to_owned),
            value: json!({"id": id}),
        }
    }

    fn unexpected<T>() -> Result<T, PolarProviderError> {
        Err(PolarProviderError::new("unexpected fake transport call"))
    }
}

#[async_trait]
impl PolarClient for FakePolarClient {
    async fn create_checkout(
        &self,
        _request: PolarCheckoutCreate,
    ) -> Result<PolarCheckout, PolarProviderError> {
        Self::unexpected()
    }

    async fn list_customers(&self, email: &str) -> Result<PolarCustomerList, PolarProviderError> {
        self.calls.lock().unwrap().push(format!("list:{email}"));
        if let Some(error) = self.list_error.lock().unwrap().take() {
            return Err(error);
        }
        let items = self.customers.lock().unwrap().clone();
        let values = items
            .iter()
            .map(|customer| customer.value.clone())
            .collect::<Vec<_>>();
        Ok(PolarCustomerList {
            value: json!({"result": {"items": values}}),
            items,
        })
    }

    async fn create_customer(
        &self,
        request: PolarCustomerCreate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        self.calls.lock().unwrap().push("create".into());
        self.creates.lock().unwrap().push(request);
        if let Some(error) = self.create_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(Self::customer("created", None))
    }

    async fn update_customer(
        &self,
        id: &str,
        request: PolarCustomerUpdate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        self.calls.lock().unwrap().push(format!("update:{id}"));
        self.updates.lock().unwrap().push((id.into(), request));
        if let Some(error) = self.update_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(Self::customer(id, None))
    }

    async fn update_customer_external(
        &self,
        external_id: &str,
        request: PolarCustomerUpdateExternal,
    ) -> Result<PolarCustomer, PolarProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("update_external:{external_id}"));
        self.external_updates
            .lock()
            .unwrap()
            .push((external_id.into(), request));
        if let Some(error) = self.update_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(Self::customer("updated", Some(external_id)))
    }

    async fn delete_customer(&self, id: &str) -> Result<(), PolarProviderError> {
        self.calls.lock().unwrap().push(format!("delete:{id}"));
        self.deletes.lock().unwrap().push(id.into());
        if let Some(error) = self.delete_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(())
    }

    async fn customer_state_external(
        &self,
        _external_id: &str,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }

    async fn create_customer_session(
        &self,
        _request: PolarCustomerSessionCreate,
    ) -> Result<PolarCustomerSession, PolarProviderError> {
        Self::unexpected()
    }

    async fn list_benefits(
        &self,
        _customer_session: &str,
        _query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }

    async fn list_customer_subscriptions(
        &self,
        _customer_session: &str,
        _query: PolarSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }

    async fn list_orders(
        &self,
        _customer_session: &str,
        _query: PolarOrderQuery,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }

    async fn list_meters(
        &self,
        _customer_session: &str,
        _query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }

    async fn list_subscriptions_by_reference(
        &self,
        _query: PolarReferenceSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }

    async fn ingest_events(
        &self,
        _request: PolarEventsIngest,
    ) -> Result<Value, PolarProviderError> {
        Self::unexpected()
    }
}

pub(super) fn user() -> crate::AuthUser {
    crate::AuthUser {
        id: Uuid::new_v4(),
        username: None,
        display_username: None,
        name: "Ada".into(),
        email: "ada@example.com".into(),
        email_verified: true,
        image: None,
        additional_fields: Default::default(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub(super) fn context() -> crate::DatabaseHookContext {
    crate::DatabaseHookContext {
        request: Some(crate::DatabaseHookRequest {
            method: "POST".into(),
            path: "/sign-up/email".into(),
            query: None,
            headers: Default::default(),
        }),
        creation_method: None,
    }
}

pub(super) fn options(client: std::sync::Arc<FakePolarClient>) -> PolarOptions {
    let mut options = PolarOptions::new(client, vec![]);
    options.create_customer_on_sign_up = true;
    options
}
