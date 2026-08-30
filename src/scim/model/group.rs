use super::{ScimMeta, invalid};
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
    #[serde(default)]
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
        self.display_name = self.display_name.trim().to_owned();
        if self.display_name.is_empty() {
            return Err(invalid("displayName cannot be empty"));
        }
        if self.external_id.as_deref() == Some("") {
            return Err(invalid("externalId cannot be empty"));
        }
        let mut seen = std::collections::HashSet::new();
        self.members
            .retain(|member| seen.insert(member.value.clone()));
        if self.members.len() > 1000 {
            return Err(invalid(
                "Groups cannot contain more than 1000 direct members",
            ));
        }
        for member in &mut self.members {
            if member.value.trim().is_empty() {
                return Err(invalid("Group members must reference a SCIM User"));
            }
            if member
                .kind
                .as_deref()
                .is_some_and(|kind| !kind.eq_ignore_ascii_case("user"))
            {
                return Err(invalid("Group members must reference a SCIM User"));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn group_with_members(values: impl IntoIterator<Item = String>) -> ScimGroup {
        ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: None,
            external_id: None,
            display_name: "Engineering".into(),
            members: values
                .into_iter()
                .map(|value| ScimGroupMember {
                    value,
                    reference: None,
                    display: None,
                    kind: None,
                })
                .collect(),
            meta: None,
        }
    }

    #[test]
    fn duplicate_members_are_collapsed_before_enforcing_the_limit() {
        let group = group_with_members(std::iter::repeat_n("user-1".into(), 1001))
            .normalize()
            .expect("duplicates do not exceed the direct-member limit");

        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].value, "user-1");
    }

    #[test]
    fn whitespace_only_member_ids_are_invalid_without_trimming_other_ids() {
        let error = group_with_members([" \t ".into()])
            .normalize()
            .expect_err("blank member identifiers must be rejected");
        assert_eq!(error.detail, "Group members must reference a SCIM User");

        let group = group_with_members([" user-1 ".into()])
            .normalize()
            .expect("nonblank identifiers remain exact");
        assert_eq!(group.members[0].value, " user-1 ");
    }
}
