use super::JwtSchema;

impl JwtSchema {
    pub(crate) fn migration_sql(&self) -> String {
        let table = quote_identifier(self.table());
        let public_key = quote_identifier(self.public_key());
        let private_key = quote_identifier(self.private_key());
        let created_at = quote_identifier(self.created_at());
        let expires_at = quote_identifier(self.expires_at());
        let alg = quote_identifier(self.alg());
        let crv = quote_identifier(self.crv());
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n\
               id TEXT PRIMARY KEY,\n\
               {public_key} TEXT NOT NULL,\n\
               {private_key} TEXT NOT NULL,\n\
               {created_at} TIMESTAMPTZ NOT NULL,\n\
               {expires_at} TIMESTAMPTZ,\n\
               {alg} TEXT,\n\
               {crv} TEXT\n\
             );\n"
        )
    }
}

pub(crate) fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_are_instance_local_quoted_and_empty_safe() {
        let schema = JwtSchema {
            model_name: Some("tenant\"jwks".into()),
            public_key_field_name: Some(String::new()),
            private_key_field_name: Some("private material".into()),
            ..JwtSchema::default()
        };
        let sql = schema.migration_sql();
        assert!(sql.contains("\"tenant\"\"jwks\""));
        assert!(sql.contains("\"public_key\" TEXT NOT NULL"));
        assert!(sql.contains("\"private material\" TEXT NOT NULL"));
    }
}
