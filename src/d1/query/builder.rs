use crate::d1::{D1Statement, D1Value};

#[derive(Default)]
pub(super) struct Query {
    sql: String,
    parameters: Vec<D1Value>,
}

impl Query {
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            parameters: Vec::new(),
        }
    }

    pub fn push(&mut self, sql: &str) -> &mut Self {
        self.sql.push_str(sql);
        self
    }

    pub fn bind(&mut self, value: D1Value) -> &mut Self {
        self.sql.push('?');
        self.parameters.push(value);
        self
    }

    pub fn finish(self) -> D1Statement {
        D1Statement::new(self.sql, self.parameters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_binding_order_without_interpolation() {
        let mut query = Query::new("select ");
        query
            .bind(D1Value::Text("' hostile ? --".into()))
            .push(", ")
            .bind(D1Value::Null);
        assert_eq!(
            query.finish(),
            D1Statement::new(
                "select ?, ?",
                vec![D1Value::Text("' hostile ? --".into()), D1Value::Null],
            )
        );
    }
}
