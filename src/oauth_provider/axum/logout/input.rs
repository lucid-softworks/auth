use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct EndSessionInput {
    pub(super) id_token_hint: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) post_logout_redirect_uri: Option<String>,
    pub(super) state: Option<String>,
}

impl EndSessionInput {
    pub(super) fn merge(self, body: Self) -> Self {
        Self {
            id_token_hint: body.id_token_hint.or(self.id_token_hint),
            client_id: body.client_id.or(self.client_id),
            post_logout_redirect_uri: body
                .post_logout_redirect_uri
                .or(self.post_logout_redirect_uri),
            state: body.state.or(self.state),
        }
    }
}

#[derive(Default, Deserialize)]
pub(super) struct ConfirmationInput {
    pub(super) action: String,
}
