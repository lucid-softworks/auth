use super::AuthService;
use crate::{AuthError, AuthSession, SessionWithUser};
use serde_json::{Map, Value};

const ACTIVE_ORGANIZATION_ID: &str = "activeOrganizationId";
const ACTIVE_TEAM_ID: &str = "activeTeamId";

impl AuthService {
    pub(crate) fn active_organization_id(session: &SessionWithUser) -> Option<String> {
        session_id(session, ACTIVE_ORGANIZATION_ID)
    }

    pub(crate) fn active_team_id(session: &SessionWithUser) -> Option<String> {
        session_id(session, ACTIVE_TEAM_ID)
    }

    pub(crate) async fn set_active_organization(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
    ) -> Result<AuthSession, AuthError> {
        let mut fields = Map::new();
        fields.insert(
            ACTIVE_ORGANIZATION_ID.into(),
            organization_id.map_or(Value::Null, |id| Value::String(id.to_string())),
        );
        fields.insert(ACTIVE_TEAM_ID.into(), Value::Null);
        self.update_session_fields_with_hooks(session, fields).await
    }

    pub(crate) async fn set_active_team(
        &self,
        session: &SessionWithUser,
        team_id: Option<String>,
    ) -> Result<AuthSession, AuthError> {
        let mut fields = Map::new();
        fields.insert(
            ACTIVE_TEAM_ID.into(),
            team_id.map_or(Value::Null, |id| Value::String(id.to_string())),
        );
        self.update_session_fields_with_hooks(session, fields).await
    }
}

fn session_id(session: &SessionWithUser, field: &str) -> Option<String> {
    session
        .session
        .additional_fields
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
}
