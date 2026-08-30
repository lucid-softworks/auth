use async_trait::async_trait;

#[async_trait]
pub trait SsoDnsResolver: Send + Sync {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>, String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSsoDnsResolver;

#[async_trait]
impl SsoDnsResolver for SystemSsoDnsResolver {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>, String> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|error| error.to_string())?
            .build()
            .map_err(|error| error.to_string())?;
        let records = resolver
            .txt_lookup(name)
            .await
            .map_err(|error| error.to_string())?;
        Ok(records
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::TXT(value) => Some(
                    value
                        .txt_data
                        .iter()
                        .flat_map(|part| part.iter().copied())
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .map(|record| String::from_utf8_lossy(&record).into_owned())
            .collect())
    }
}
