use std::sync::Arc;

use crate::AxumPluginRoute;

use super::super::{OAuthProviderConfig, OAuthProviderStore};

/// Better Auth 1.7.1 marks every OAuth resource-management endpoint as
/// `SERVER_ONLY`. Consequently none of them is installed in the native HTTP
/// router: direct requests must resolve to 404 just as they do upstream.
///
/// Resource persistence remains available through `OAuthProviderStore` for a
/// host's trusted, in-process administration layer. Exposing that layer over
/// HTTP would turn server-only operations into public plugin endpoints and
/// would not be Better Auth compatible.
pub(super) fn routes(
    _config: Arc<OAuthProviderConfig>,
    _store: Arc<dyn OAuthProviderStore>,
) -> Vec<AxumPluginRoute> {
    Vec::new()
}
