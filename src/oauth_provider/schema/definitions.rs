use super::{OAuthProviderModelSchema, OAuthProviderSchema};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthProviderModel {
    Client,
    Resource,
    ClientResource,
    RefreshToken,
    AccessToken,
    Consent,
    ClientAssertion,
}

#[derive(Clone, Copy)]
enum Reference {
    Core(&'static str),
    Provider(OAuthProviderModel, &'static str),
}

#[derive(Clone, Copy)]
struct FieldDefinition {
    logical: &'static str,
    reference: Option<Reference>,
    on_delete: Option<&'static str>,
    index: bool,
}

struct ModelDefinition {
    model: OAuthProviderModel,
    logical_name: &'static str,
    fields: &'static [FieldDefinition],
    unique: &'static [&'static [&'static str]],
}

macro_rules! field {
    ($logical:literal) => {
        FieldDefinition {
            logical: $logical,
            reference: None,
            on_delete: None,
            index: false,
        }
    };
}

macro_rules! indexed {
    ($logical:literal) => {
        FieldDefinition {
            index: true,
            ..field!($logical)
        }
    };
}

macro_rules! referenced {
    ($logical:literal, $reference:expr, $on_delete:expr) => {
        FieldDefinition {
            logical: $logical,
            reference: Some($reference),
            on_delete: $on_delete,
            index: true,
        }
    };
}

const CLIENT_FIELDS: &[FieldDefinition] = &[
    field!("clientId"),
    field!("clientSecret"),
    field!("clientDiscoveryId"),
    field!("disabled"),
    field!("skipConsent"),
    field!("enableEndSession"),
    field!("subjectType"),
    field!("scopes"),
    field!("clientCredentialsScopes"),
    referenced!("userId", Reference::Core("user"), None),
    field!("createdAt"),
    field!("updatedAt"),
    field!("name"),
    field!("uri"),
    field!("icon"),
    field!("contacts"),
    field!("tos"),
    field!("policy"),
    field!("softwareId"),
    field!("softwareVersion"),
    field!("softwareStatement"),
    field!("redirectUris"),
    field!("postLogoutRedirectUris"),
    field!("backchannelLogoutUri"),
    field!("backchannelLogoutSessionRequired"),
    field!("tokenEndpointAuthMethod"),
    field!("applicationType"),
    field!("jwks"),
    field!("jwksUri"),
    field!("grantTypes"),
    field!("responseTypes"),
    field!("requirePKCE"),
    field!("dpopBoundAccessTokens"),
    field!("referenceId"),
    field!("metadata"),
];

const RESOURCE_FIELDS: &[FieldDefinition] = &[
    field!("identifier"),
    field!("name"),
    field!("accessTokenTtl"),
    field!("refreshTokenTtl"),
    field!("signingAlgorithm"),
    field!("signingKeyId"),
    field!("allowedScopes"),
    field!("customClaims"),
    field!("dpopBoundAccessTokensRequired"),
    field!("disabled"),
    field!("createdAt"),
    field!("updatedAt"),
    field!("policyVersion"),
    field!("metadata"),
];

const CLIENT_RESOURCE_FIELDS: &[FieldDefinition] = &[
    referenced!(
        "clientId",
        Reference::Provider(OAuthProviderModel::Client, "clientId"),
        Some("CASCADE")
    ),
    referenced!(
        "resourceId",
        Reference::Provider(OAuthProviderModel::Resource, "identifier"),
        Some("CASCADE")
    ),
    field!("metadata"),
    field!("createdAt"),
];

const REFRESH_FIELDS: &[FieldDefinition] = &[
    field!("token"),
    referenced!(
        "clientId",
        Reference::Provider(OAuthProviderModel::Client, "clientId"),
        None
    ),
    referenced!("sessionId", Reference::Core("session"), Some("SET NULL")),
    referenced!("userId", Reference::Core("user"), None),
    field!("referenceId"),
    indexed!("authorizationCodeId"),
    field!("resources"),
    field!("requestedUserInfoClaims"),
    field!("expiresAt"),
    field!("createdAt"),
    field!("revoked"),
    field!("rotatedAt"),
    field!("rotationReplayResponse"),
    field!("rotationReplayExpiresAt"),
    field!("authTime"),
    field!("confirmation"),
    field!("scopes"),
];

const ACCESS_FIELDS: &[FieldDefinition] = &[
    field!("token"),
    referenced!(
        "clientId",
        Reference::Provider(OAuthProviderModel::Client, "clientId"),
        None
    ),
    referenced!("sessionId", Reference::Core("session"), Some("SET NULL")),
    referenced!("userId", Reference::Core("user"), None),
    field!("referenceId"),
    indexed!("authorizationCodeId"),
    field!("resources"),
    field!("requestedUserInfoClaims"),
    referenced!(
        "refreshId",
        Reference::Provider(OAuthProviderModel::RefreshToken, "id"),
        None
    ),
    field!("expiresAt"),
    field!("createdAt"),
    field!("revoked"),
    field!("confirmation"),
    field!("scopes"),
];

const CONSENT_FIELDS: &[FieldDefinition] = &[
    referenced!(
        "clientId",
        Reference::Provider(OAuthProviderModel::Client, "clientId"),
        None
    ),
    referenced!("userId", Reference::Core("user"), None),
    field!("referenceId"),
    field!("resources"),
    field!("requestedUserInfoClaims"),
    field!("scopes"),
    field!("createdAt"),
    field!("updatedAt"),
];

const ASSERTION_FIELDS: &[FieldDefinition] = &[field!("jti"), field!("expiresAt")];

const DEFINITIONS: &[ModelDefinition] = &[
    ModelDefinition {
        model: OAuthProviderModel::Client,
        logical_name: "oauthClient",
        fields: CLIENT_FIELDS,
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::Resource,
        logical_name: "oauthResource",
        fields: RESOURCE_FIELDS,
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::ClientResource,
        logical_name: "oauthClientResource",
        fields: CLIENT_RESOURCE_FIELDS,
        unique: &[&["clientId", "resourceId"]],
    },
    ModelDefinition {
        model: OAuthProviderModel::RefreshToken,
        logical_name: "oauthRefreshToken",
        fields: REFRESH_FIELDS,
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::AccessToken,
        logical_name: "oauthAccessToken",
        fields: ACCESS_FIELDS,
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::Consent,
        logical_name: "oauthConsent",
        fields: CONSENT_FIELDS,
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::ClientAssertion,
        logical_name: "oauthClientAssertion",
        fields: ASSERTION_FIELDS,
        unique: &[&["jti"]],
    },
];
