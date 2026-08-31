use crate::AuthError;
use mongodb::bson::Document;
use serde_json::{Map, Value};

pub(in crate::mongodb) mod execute;
mod join;
mod predicate;

/// One Better Auth adapter predicate using a logical schema field.
#[derive(Debug, Clone, PartialEq)]
pub struct MongoFilter {
    pub field: String,
    pub value: Value,
    pub operator: MongoFilterOperator,
    pub connector: MongoFilterConnector,
    pub mode: MongoComparisonMode,
}

impl MongoFilter {
    pub fn equal(field: impl Into<String>, value: Value) -> Self {
        Self {
            field: field.into(),
            value,
            operator: MongoFilterOperator::Eq,
            connector: MongoFilterConnector::And,
            mode: MongoComparisonMode::Sensitive,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MongoFilterOperator {
    #[default]
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

impl MongoFilterOperator {
    pub fn parse(value: &str) -> Result<Self, super::MongoAdapterError> {
        match value.to_ascii_lowercase().as_str() {
            "eq" => Ok(Self::Eq),
            "ne" => Ok(Self::Ne),
            "gt" => Ok(Self::Gt),
            "gte" => Ok(Self::Gte),
            "lt" => Ok(Self::Lt),
            "lte" => Ok(Self::Lte),
            "in" => Ok(Self::In),
            "not_in" => Ok(Self::NotIn),
            "contains" => Ok(Self::Contains),
            "starts_with" => Ok(Self::StartsWith),
            "ends_with" => Ok(Self::EndsWith),
            operator => Err(super::MongoAdapterError::unsupported_operator(operator)),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MongoFilterConnector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MongoComparisonMode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoSort {
    pub field: String,
    pub direction: MongoSortDirection,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MongoSortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MongoJoinRelation {
    OneToOne,
    #[default]
    OneToMany,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoJoin {
    pub model: String,
    pub local_field: String,
    pub foreign_field: String,
    pub relation: MongoJoinRelation,
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MongoFindOptions {
    pub select: Vec<String>,
    pub sort: Option<MongoSort>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub joins: Vec<MongoJoin>,
    /// Better Auth's join fallback is 100.
    pub default_find_many_limit: Option<u64>,
}

/// Explicit MongoDB transaction. Dropping the value ends its session.
pub struct MongoTransaction {
    pub(super) session: Option<mongodb::ClientSession>,
    pub(super) store: super::MongoStore,
    finished: bool,
}

pub(in crate::mongodb) trait MongoExecution {
    fn parts(&mut self) -> (&super::MongoStore, Option<&mut mongodb::ClientSession>);
}

impl MongoExecution for MongoTransaction {
    fn parts(&mut self) -> (&super::MongoStore, Option<&mut mongodb::ClientSession>) {
        (&self.store, self.session.as_mut())
    }
}

impl super::MongoStore {
    pub async fn begin(&self) -> Result<MongoTransaction, AuthError> {
        let session = if self.transactions_enabled() {
            let mut session = self
                .client
                .as_ref()
                .expect("enabled MongoDB transactions have a client")
                .start_session()
                .await
                .map_err(storage)?;
            session.start_transaction().await.map_err(storage)?;
            Some(session)
        } else {
            None
        };
        Ok(MongoTransaction {
            session,
            store: self.clone(),
            finished: false,
        })
    }

    pub async fn insert_record(
        &self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::insert_with_session(self, None, model, record).await
    }

    pub(super) async fn insert_required_record(
        &self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError> {
        self.insert_record(model, record)
            .await?
            .ok_or(AuthError::NotFound)
    }

    pub async fn find_record(
        &self,
        model: &str,
        filters: &[MongoFilter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::find_one_with_session(self, None, model, filters, select, &[]).await
    }

    pub async fn find_records(
        &self,
        model: &str,
        filters: &[MongoFilter],
        options: &MongoFindOptions,
    ) -> Result<Vec<Map<String, Value>>, AuthError> {
        execute::find_many_with_session(self, None, model, filters, options).await
    }

    pub async fn update_record(
        &self,
        model: &str,
        filters: &[MongoFilter],
        values: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::update_one_with_session(self, None, model, filters, values).await
    }

    pub async fn update_records(
        &self,
        model: &str,
        filters: &[MongoFilter],
        values: Map<String, Value>,
    ) -> Result<u64, AuthError> {
        execute::update_many_with_session(self, None, model, filters, values).await
    }

    pub async fn count_records(
        &self,
        model: &str,
        filters: &[MongoFilter],
    ) -> Result<u64, AuthError> {
        execute::count_with_session(self, None, model, filters).await
    }

    pub async fn delete_record(
        &self,
        model: &str,
        filters: &[MongoFilter],
    ) -> Result<(), AuthError> {
        execute::delete_one_with_session(self, None, model, filters).await
    }

    pub async fn delete_records(
        &self,
        model: &str,
        filters: &[MongoFilter],
    ) -> Result<u64, AuthError> {
        execute::delete_many_with_session(self, None, model, filters).await
    }

    pub async fn consume_record(
        &self,
        model: &str,
        filters: &[MongoFilter],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::consume_one_with_session(self, None, model, filters).await
    }

    pub async fn increment_record(
        &self,
        model: &str,
        filters: &[MongoFilter],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::increment_one_with_session(self, None, model, filters, increments, set).await
    }
}

impl MongoTransaction {
    pub async fn insert_record(
        &mut self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::insert_with_session(&self.store, self.session.as_mut(), model, record).await
    }

    pub async fn find_record(
        &mut self,
        model: &str,
        filters: &[MongoFilter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::find_one_with_session(&self.store, self.session.as_mut(), model, filters, select, &[]).await
    }

    pub async fn update_record(
        &mut self,
        model: &str,
        filters: &[MongoFilter],
        values: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::update_one_with_session(&self.store, self.session.as_mut(), model, filters, values).await
    }

    pub async fn delete_records(
        &mut self,
        model: &str,
        filters: &[MongoFilter],
    ) -> Result<u64, AuthError> {
        execute::delete_many_with_session(&self.store, self.session.as_mut(), model, filters).await
    }

    pub async fn consume_record(
        &mut self,
        model: &str,
        filters: &[MongoFilter],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::consume_one_with_session(&self.store, self.session.as_mut(), model, filters).await
    }

    pub async fn increment_record(
        &mut self,
        model: &str,
        filters: &[MongoFilter],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::increment_one_with_session(
            &self.store,
            self.session.as_mut(),
            model,
            filters,
            increments,
            set,
        )
        .await
    }

    pub async fn commit(mut self) -> Result<(), AuthError> {
        if let Some(session) = &mut self.session {
            session.commit_transaction().await.map_err(storage)?;
        }
        self.finished = true;
        Ok(())
    }

    pub async fn rollback(mut self) -> Result<(), AuthError> {
        if let Some(session) = &mut self.session {
            session.abort_transaction().await.map_err(storage)?;
        }
        self.finished = true;
        Ok(())
    }
}

pub(super) fn projection(
    model: &super::schema::MongoModel<'_>,
    select: &[String],
) -> Result<Option<Document>, AuthError> {
    if select.is_empty() {
        return Ok(None);
    }
    let mut projection = Document::new();
    for field in select {
        projection.insert(model.physical_field(field)?, 1);
    }
    Ok(Some(projection))
}

fn storage(error: mongodb::error::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
