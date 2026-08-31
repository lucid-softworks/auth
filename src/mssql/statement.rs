use super::value::MssqlValue;
use crate::AuthError;
use tiberius::Row;

pub(super) struct MssqlStatement {
    sql: String,
    params: Vec<MssqlValue>,
}

impl MssqlStatement {
    pub(super) fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
        }
    }

    pub(super) fn push(&mut self, sql: impl AsRef<str>) -> &mut Self {
        self.sql.push_str(sql.as_ref());
        self
    }

    pub(super) fn bind(&mut self, value: MssqlValue) -> &mut Self {
        self.params.push(value);
        self.sql.push_str("@P");
        self.sql.push_str(&self.params.len().to_string());
        self
    }

    #[cfg(test)]
    pub(super) fn sql(&self) -> &str {
        &self.sql
    }

    pub(super) fn into_query(self) -> tiberius::Query<'static> {
        let mut query = tiberius::Query::new(self.sql);
        for param in self.params {
            param.bind(&mut query);
        }
        query
    }

    pub(super) async fn query(
        self,
        client: &mut super::adapter::MssqlClient,
    ) -> Result<Vec<Row>, AuthError> {
        self.into_query()
            .query(client)
            .await
            .map_err(storage)?
            .into_first_result()
            .await
            .map_err(storage)
    }

    pub(super) async fn execute(
        self,
        client: &mut super::adapter::MssqlClient,
    ) -> Result<u64, AuthError> {
        self.into_query()
            .execute(client)
            .await
            .map(|result| result.total())
            .map_err(storage)
    }
}

fn storage(error: tiberius::error::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_tiberius_parameters_in_order() {
        let mut statement = MssqlStatement::new("select ");
        statement
            .bind(MssqlValue::Integer(Some(7)))
            .push(", ")
            .bind(MssqlValue::Text(Some("value".into())));
        assert_eq!(statement.sql(), "select @P1, @P2");
    }
}
