use super::{ScimMeta, bounded, invalid, optional_bounded};
use crate::scim::{SCIM_GROUP_SCHEMA, ScimError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimGroupMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimGroupMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

impl ScimGroup {
    pub fn normalize(mut self) -> Result<Self, ScimError> {
        if self.schemas != [SCIM_GROUP_SCHEMA] {
            return Err(invalid(
                "schemas must contain only the core SCIM Group schema",
            ));
        }
        self.display_name = bounded(self.display_name, 1024, "displayName")?;
        self.external_id = optional_bounded(self.external_id, 1024, "externalId")?;
        if self.members.len() > 1000 {
            return Err(invalid("members must contain at most 1000 values"));
        }
        let mut seen = std::collections::HashSet::new();
        self.members
            .retain(|member| seen.insert(member.value.clone()));
        for member in &mut self.members {
            member.value = bounded(member.value.clone(), 256, "members.value")?;
            if member
                .kind
                .as_deref()
                .is_some_and(|kind| !kind.eq_ignore_ascii_case("user"))
            {
                return Err(invalid("Group members must reference User resources"));
            }
            member.kind = Some("User".into());
            member.reference = None;
            member.display = None;
        }
        self.id = None;
        self.meta = None;
        Ok(self)
    }
}
