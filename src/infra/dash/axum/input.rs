use crate::{DashSortDirection, DashUserListQuery};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserListQuery {
    limit: Option<f64>,
    offset: Option<f64>,
    sort_by: Option<String>,
    sort_order: Option<DashSortDirection>,
    #[serde(rename = "where")]
    where_clause: Option<String>,
    count_where: Option<String>,
}

impl UserListQuery {
    pub(super) fn into_domain(self) -> Result<DashUserListQuery, serde_json::Error> {
        Ok(DashUserListQuery {
            limit: self.limit,
            offset: self.offset,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            where_clause: parse_where(self.where_clause)?,
            count_where: parse_where(self.count_where)?,
        })
    }
}

fn parse_where(value: Option<String>) -> Result<Option<Vec<Value>>, serde_json::Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed: Value = serde_json::from_str(&value)?;
    Ok(Some(parsed.as_array().cloned().unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
pub(super) struct CallbackBody {
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PasswordBody {
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnlinkBody {
    pub provider_id: String,
    pub account_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserIdBody {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BanBody {
    pub ban_reason: Option<String>,
    pub ban_expires: Option<i64>,
    #[serde(default = "default_true")]
    pub delete_all_sessions: bool,
}

const fn default_true() -> bool {
    true
}
