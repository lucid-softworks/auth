use axum::{http::HeaderMap, response::Response};

use crate::oauth_provider::{
    OAuthProviderConfig, OAuthProviderStore, OAuthUiStage, authorization::OAuthAuthorizationQuery,
};
use crate::{AuthService, OAuthProviderError, SessionWithUser};

use super::{
    helpers::{callback_context, redirect, signed_query, storage_error},
    redirect_error,
};

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct AuthorizationStageState {
    pub(super) selected: bool,
    pub(super) created: bool,
    pub(super) post_login: bool,
}

pub(super) struct UiStageRequest<'a> {
    pub(super) query: &'a OAuthAuthorizationQuery,
    pub(super) scopes: &'a [String],
    pub(super) prompt: &'a [String],
    pub(super) session: &'a SessionWithUser,
    pub(super) stages: AuthorizationStageState,
}

pub(super) async fn ui_stage_response(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    request: UiStageRequest<'_>,
) -> Result<Option<Response>, OAuthProviderError> {
    let context = callback_context(headers, request.session, request.scopes);
    let candidates = [
        (
            !request.stages.selected,
            OAuthUiStage::SelectAccount,
            config.select_account_page.as_deref(),
        ),
        (!request.stages.created, OAuthUiStage::Signup, None),
        (
            !request.stages.post_login,
            OAuthUiStage::PostLogin,
            config.post_login_page.as_deref(),
        ),
    ];
    for (eligible, stage, configured_page) in candidates {
        if !eligible {
            continue;
        }
        let prompted = stage != OAuthUiStage::SelectAccount
            || request.prompt.iter().any(|value| value == "select_account");
        let callback_page = match (&config.callbacks.ui_redirect, prompted) {
            (Some(callback), true) => callback
                .redirect(stage, &context)
                .await
                .map_err(storage_error)?,
            _ => None,
        };
        let page = callback_page
            .as_deref()
            .or(configured_page)
            .filter(|_| prompted);
        if let Some(page) = page {
            if request.prompt.iter().any(|value| value == "none") {
                let (code, description) = stage_prompt_error(stage);
                return redirect_error(
                    service,
                    config,
                    store,
                    headers,
                    request.query,
                    code,
                    description,
                )
                .await
                .map(Some);
            }
            return Ok(Some(redirect(
                headers,
                &format!("{page}?{}", signed_query(service, config, request.query)),
            )));
        }
    }
    Ok(None)
}

fn stage_prompt_error(stage: OAuthUiStage) -> (&'static str, &'static str) {
    match stage {
        OAuthUiStage::SelectAccount => (
            "account_selection_required",
            "End-User account selection is required",
        ),
        OAuthUiStage::Signup | OAuthUiStage::PostLogin => {
            ("interaction_required", "End-User interaction is required")
        }
    }
}
