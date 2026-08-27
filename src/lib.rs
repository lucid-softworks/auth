//! Native authentication with a Better Auth-compatible HTTP surface.

mod additional_fields;
mod admin;
mod agent_auth;
mod anonymous;
mod api_key;
mod audit;
mod autumn;
mod bearer;
mod captcha;
mod chargebee;
mod client_ip;
mod commet;
mod config;
mod cookie;
mod creem;
mod database_hooks;
mod database_schema;
pub mod device_authorization;
mod dodo_payments;
mod dub;
mod electron;
mod email;
mod email_otp;
mod error;
mod expo;
mod exports;
mod generic_oauth;
mod guest_capability;
mod have_i_been_pwned;
mod i18n;
pub mod infra;
mod jwt;
mod last_login_method;
mod magic_link;
mod mcp;
mod memory;
mod model;
mod multi_session;
mod oauth;
mod oauth_popup;
mod oauth_provider;
mod oauth_proxy;
mod one_tap;
mod one_time_token;
mod open_api;
mod operator_security;
mod organization;
mod origin;
mod owner_policy;
mod passkey;
mod phone_number;
mod plugin;
mod polar;
mod rate_limit;
mod secondary_storage;
mod service;
#[cfg(feature = "axum")]
mod session_cache;
mod session_config;
mod siwe;
mod step_up;
mod store;
mod stripe;
mod symmetric_crypto;
#[cfg(feature = "axum")]
mod symmetric_jwe;
mod test_utils;
mod two_factor;
mod user_deletion;
mod username;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod protocol;

pub use additional_fields::{
    AdditionalField, AdditionalFieldDefault, AdditionalFieldOnDelete, AdditionalFieldReference,
    AdditionalFieldSet, AdditionalFieldTransform, AdditionalFieldType, AdditionalFieldValidator,
};
pub use admin::{
    AdminConfig, AdminCreateUser, AdminError, AdminListCondition, AdminListOperator,
    AdminListUsersQuery, AdminPermissionSet, AdminPlugin, AdminRole, AdminSchema,
    AdminSortDirection, AdminUserUpdate,
};
pub use anonymous::{
    AnonymousEmailGenerator, AnonymousLinkAccount, AnonymousLinkAccountCallback,
    AnonymousNameGenerator, AnonymousPlugin, AnonymousPluginConfig, AnonymousSignInContext,
};
pub use api_key::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyExpirationConfig, ApiKeyGenerator, ApiKeyGetter,
    ApiKeyGetterValue, ApiKeyOptions, ApiKeyPlugin, ApiKeyRateLimitConfig, ApiKeyReference,
    ApiKeySecondaryStorage, ApiKeySecondaryStorageMode, ApiKeyStartingCharactersConfig,
    ApiKeyStorage, ApiKeyValidator,
};
pub use database_hooks::{
    BeforeDatabaseCreateHook, BeforeDatabaseHook, DatabaseCreatePatch, DatabaseCreateRecord,
    DatabaseHookContext, DatabaseHookRequest, DatabaseHooks, DatabaseModel, DatabaseRecord,
    DeferredHookResponse,
};
pub use database_schema::*;
pub use email::{
    EmailVerificationConfig, PasswordResetCallback, PasswordResetEmail, PasswordResetEmailSender,
    VerificationEmail, VerificationEmailSender,
};
pub use email_otp::{
    EmailOtpChangeEmailConfig, EmailOtpConfig, EmailOtpEncryptor, EmailOtpError, EmailOtpGenerator,
    EmailOtpHasher, EmailOtpMessage, EmailOtpPlugin, EmailOtpRequestContext,
    EmailOtpResendStrategy, EmailOtpSender, EmailOtpSignInInput, EmailOtpStorage, EmailOtpType,
    EmailOtpVerification,
};
pub use exports::*;
pub use generic_oauth::{
    Auth0Options, BaseOAuthProviderOptions, GenericOAuthAccountIssuer,
    GenericOAuthAccountKeyContext, GenericOAuthAccountSubject, GenericOAuthConfig,
    GenericOAuthError, GenericOAuthMappedUser, GenericOAuthPlugin, GenericOAuthPresetError,
    GenericOAuthProfileMapper, GenericOAuthRefreshContext, GenericOAuthRefreshParams,
    GenericOAuthTokenExchange, GenericOAuthTokenRequest, GenericOAuthUserInfo, GumroadOptions,
    HubSpotOptions, INVALID_OAUTH_CONFIGURATION, KeycloakOptions, LineOptions,
    MicrosoftEntraIdOptions, OktaOptions, PatreonOptions, SlackOptions, TOKEN_URL_NOT_FOUND,
    YandexOptions, auth0, gumroad, hubspot, keycloak, line, microsoft_entra_id, okta, patreon,
    slack, yandex,
};
pub use guest_capability::{
    GuestCapabilityPlugin, GuestCapabilityPrincipal, GuestCapabilityStore, GuestGrant,
    GuestGrantSignInResult, IssuedGuestGrant, NewGuestGrant,
};
pub use jwt::{
    ExportedKeyPair, JwkAlgorithm, JwkStore, JwtAdapterConfig, JwtAdapterContext, JwtAudience,
    JwtClaimsConfig, JwtConfig, JwtError, JwtExpiration, JwtJwkCreator, JwtJwksConfig,
    JwtJwksReader, JwtOverrideOptions, JwtPayloadDefinition, JwtPlugin, JwtProtectedHeader,
    JwtRemoteSigner, JwtSchema, JwtService, JwtSession, JwtSigningOverrides, JwtSubjectResolver,
    NewJwk, ResolvedSigningKey, StoredJwk, generate_exported_key_pair, to_exp_jwt,
};
pub use last_login_method::{
    BeforeStoreLastLoginMethod, LastLoginMethodConfig, LastLoginMethodContext,
    LastLoginMethodPlugin, LastLoginMethodResolver, LastLoginMethodSchema,
    LastLoginMethodUserSchema,
};
pub use magic_link::{
    MagicLinkConfig, MagicLinkEmail, MagicLinkPlugin, MagicLinkRequestContext, MagicLinkSender,
    MagicLinkTokenGenerator, MagicLinkTokenHasher, MagicLinkTokenStorage,
};
pub use model::{
    ApiKey, AuthSession, AuthUser, AuthenticationMethod, IssuedApiKey, NewApiKey, NewPasswordUser,
    OAuthAccount, Principal, SessionWithUser, StoredPasskey, VerificationValue, VerifiedApiKey,
};
pub use multi_session::{INVALID_SESSION_TOKEN, MultiSessionConfig, MultiSessionPlugin};
pub use oauth::{
    AuthorizationRequest, BuiltinProvider, BuiltinProviderKind, OAuthClientAssertion,
    OAuthClientAssertionContext, OAuthGrantType, OAuthProviderConfig, OAuthRefreshContext,
    OAuthRequestContext, OAuthTokens, OAuthUserInfo, OidcConfig, ProfileMap, SocialProvider,
    TokenEndpointAuth,
};
pub use oauth_popup::{
    OAUTH_POPUP_DATA_ELEMENT_ID, OAUTH_POPUP_MESSAGE_TYPE, OAUTH_POPUP_SCRIPT_CSP_HASH,
    OAuthPopupPlugin, POPUP_MARKER_COOKIE, POPUP_TOKEN_STORAGE_KEY,
};
pub use oauth_provider::*;
pub use oauth_proxy::{
    OAuthProxyConfig, OAuthProxyPlugin, OAuthProxySecret, OAuthProxyVersionedSecret,
};
pub use one_tap::{OneTapConfig, OneTapError, OneTapPlugin};
pub use one_time_token::{
    OneTimeTokenConfig, OneTimeTokenError, OneTimeTokenGenerator, OneTimeTokenHasher,
    OneTimeTokenPlugin, OneTimeTokenRequestContext, OneTimeTokenStorage,
};
pub use operator_security::{
    OperatorSecurityConfig, OperatorSecurityError, OperatorSecurityPlugin, OperatorSecurityService,
    OperatorSecurityStatus, OperatorSecurityStore,
};
pub use organization::{
    FullOrganization, MemoryOrganizationStore, NewOrganization, NewOrganizationInvitation,
    Organization, OrganizationCreateOutcome, OrganizationCreation, OrganizationCreationPolicy,
    OrganizationDataStore, OrganizationDynamicAccessControlConfig, OrganizationError,
    OrganizationErrorStatus, OrganizationInvitation, OrganizationInvitationAcceptance,
    OrganizationInvitationDetails, OrganizationInvitationEmail, OrganizationInvitationEmailSender,
    OrganizationInvitationStatus, OrganizationInvitationStore, OrganizationInvitationWriteOutcome,
    OrganizationLifecycleHooks, OrganizationMember, OrganizationMemberStore,
    OrganizationMemberWithUser, OrganizationMemberWriteOutcome, OrganizationPermissions,
    OrganizationPlugin, OrganizationPluginConfig, OrganizationRole, OrganizationRoleStore,
    OrganizationSchema, OrganizationStore, OrganizationTeam, OrganizationTeamMember,
    OrganizationTeamStore, OrganizationTeamWriteOutcome, OrganizationTeamsConfig,
    OrganizationUpdate,
};
pub use owner_policy::OwnerPolicyPlugin;
pub use passkey::{
    PasskeyAuthenticationCallback, PasskeyAuthenticationConfig, PasskeyAuthenticationVerified,
    PasskeyAuthenticatorSelection, PasskeyConfig, PasskeyExtensions, PasskeyExtensionsResolver,
    PasskeyPlugin, PasskeyRegistrationCallback, PasskeyRegistrationConfig,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyRegistrationUserResolver,
    PasskeyRegistrationVerified,
};
pub use phone_number::{
    PhoneNumberConfig, PhoneNumberError, PhoneNumberMessage, PhoneNumberOtpSender,
    PhoneNumberOtpVerifier, PhoneNumberPlugin, PhoneNumberRequestContext, PhoneNumberSchema,
    PhoneNumberSignInInput, PhoneNumberSignUpConfig, PhoneNumberStore, PhoneNumberTemporaryEmail,
    PhoneNumberTemporaryName, PhoneNumberValidator, PhoneNumberVerification,
    PhoneNumberVerificationCallback, PhoneNumberVerified, PhoneNumberVerifyInput,
    PhoneNumberWriteOutcome,
};
pub use plugin::{
    AfterAuthEvent, AuthActivity, AuthPlugin, BeforeAuthEvent, PasswordCredentialChanged,
    PasswordCredentialSource, PluginApiError, PluginArtifactMetadata, PluginClientMetadata,
    PluginClientPathMethod, PluginClientProvenance, PluginCookie, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginMiddleware, PluginMigration, PluginMigrationContribution,
    PluginProvenance, PluginRateLimit, PluginRequestContext, PluginRequestSecurity,
    SensitiveOperation, UserManagementAction, UserManagementDecision, UserManagementOperation,
};
#[cfg(feature = "axum")]
pub use plugin::{AxumPluginRoute, PluginSession};
pub use rate_limit::{
    RateLimitConfig, RateLimitCustomRule, RateLimitOutcome, RateLimitRequest, RateLimitRule,
    RateLimitRuleResolver, RateLimitStorage, RateLimitStorageMode,
};
pub use service::account_types::{
    LinkedAccount, ProviderAccountIdentity, ProviderAccountInfo, ProviderAccountUser,
    ProviderTokenResponse,
};
pub use service::{
    ApiKeySortDirection, ApiKeyUpdate, AuthService, DeleteUserResult, EmailSignUpInput,
    EmailSignUpResult, EmailVerificationResult, HashedPasswordUser, OAuthCallbackResult,
    PasskeyRegistrationRequest, PasskeyRegistrationResult, PasskeyRegistrationVerification,
    PasswordChangeResult, SignInResult, SocialIdTokenInput, SocialSignInInput, SocialSignInResult,
};
pub use session_config::{
    CookieCacheConfig, CookieCacheRefresh, CookieCacheStrategy, SessionConfig, SessionStorageMode,
};
pub use siwe::{
    SiweCacao, SiweConfig, SiweEnsLookup, SiweEnsProfile, SiweError, SiweIdentityWrite,
    SiweIdentityWriteOutcome, SiweMessageVerifier, SiweNonceGenerator, SiwePlugin, SiweSchema,
    SiweStore, SiweVerificationRequest, SiweVerificationResult, WalletAddress, WalletAddressOwner,
};
pub use step_up::{
    MemoryStepUpStore, RecoveryCodeStatus, StepUpAssurance, StepUpError, StepUpPolicyConfig,
    StepUpPolicyPlugin, StepUpPolicyService, StepUpSession, StepUpSessionProjection, StepUpStore,
};
pub use store::{
    AccessStore, AccountDeleteOutcome, ApiKeyStore, ApiKeyUseOutcome, AuthStore,
    DatabaseAccountCreate, DatabaseAccountOwnerWrite, DatabaseCreate, DatabaseIdInput,
    DatabaseIdPlan, DatabaseIdSupplier, DatabaseIdValue, DatabaseWrite, DatabaseWriteOperation,
    DependentAccountContext, DependentAccountPreparer, OAuthAccountOwner, OAuthAccountStore,
    OAuthTokenUpdateOutcome, PasskeyDeleteOutcome, PreparedDatabaseId, SecurityStore,
    UserProfileUpdate, VerificationStore,
};
pub use user_deletion::{
    ChangeEmailConfig, ChangeEmailConfirmation, ChangeEmailConfirmationSender,
    DeleteAccountVerification, DeleteAccountVerificationSender, DeleteUserConfig, UserConfig,
    UserDeletionCallback,
};
