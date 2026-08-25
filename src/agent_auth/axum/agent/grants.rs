use crate::{AgentAuthConfig, AgentCapabilityGrant, AgentGrantStatus};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub(super) fn format(grants: Vec<AgentCapabilityGrant>, config: &AgentAuthConfig) -> Vec<Value> {
    let mut best: BTreeMap<String, AgentCapabilityGrant> = BTreeMap::new();
    for grant in grants
        .into_iter()
        .filter(|grant| grant.status != AgentGrantStatus::Consumed)
    {
        let replace = best.get(&grant.capability).is_none_or(|existing| {
            priority(grant.status) < priority(existing.status)
                || (priority(grant.status) == priority(existing.status)
                    && grant.created_at > existing.created_at)
        });
        if replace {
            best.insert(grant.capability.clone(), grant);
        }
    }
    best.into_values()
        .map(|grant| {
            let mut value = Map::from_iter([
                ("capability".into(), json!(grant.capability)),
                ("status".into(), json!(grant.status)),
            ]);
            if grant.status == AgentGrantStatus::Active {
                if let Some(granted_by) = grant.granted_by {
                    value.insert("granted_by".into(), json!(granted_by));
                }
                if let Some(constraints) = grant.constraints {
                    value.insert("constraints".into(), json!(constraints));
                }
                if let Some(expires_at) = grant.expires_at {
                    value.insert("expires_at".into(), json!(expires_at));
                }
                let capability = value["capability"].as_str().unwrap_or_default();
                if let Some(definition) = config
                    .capabilities
                    .iter()
                    .find(|definition| definition.name == capability)
                {
                    value.insert("description".into(), json!(definition.description));
                    if let Some(input) = &definition.input {
                        value.insert("input".into(), json!(input));
                    }
                }
            }
            Value::Object(value)
        })
        .collect()
}

fn priority(status: AgentGrantStatus) -> u8 {
    match status {
        AgentGrantStatus::Active => 0,
        AgentGrantStatus::Pending => 1,
        AgentGrantStatus::Denied => 2,
        AgentGrantStatus::Revoked => 3,
        AgentGrantStatus::Consumed => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    fn grant(id: &str, status: AgentGrantStatus, age: i64) -> AgentCapabilityGrant {
        let now = Utc::now() + Duration::seconds(age);
        AgentCapabilityGrant {
            id: id.into(),
            agent_id: "agent".into(),
            capability: "mail.read".into(),
            constraints: None,
            denied_by: None,
            granted_by: Some(Uuid::nil()),
            expires_at: None,
            status,
            reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn active_grant_wins_and_consumed_grants_are_omitted() {
        let values = format(
            vec![
                grant("revoked", AgentGrantStatus::Revoked, 2),
                grant("active", AgentGrantStatus::Active, 1),
                grant("consumed", AgentGrantStatus::Consumed, 3),
            ],
            &AgentAuthConfig::default(),
        );
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["status"], "active");
    }
}
