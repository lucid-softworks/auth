//! Native authentication with a Better Auth-compatible HTTP surface.

mod additional_fields;
mod admin;
mod anonymous;
mod api_key;
mod audit;
mod bearer;
mod breached_password;
mod client_ip;
mod config;
mod cookie;
mod database_hooks;
mod email;
mod email_otp;
mod error;
mod generic_oauth;
mod guest_capability;
mod jwt;
mod last_login_method;
mod magic_link;
mod memory;
mod model;
mod multi_session;
mod oauth;
mod oauth_popup;
mod oauth_proxy;
mod one_tap;
mod one_time_token;
mod operator_security;
mod organization;
mod origin;
mod owner_policy;
mod passkey;
mod phone_number;
mod plugin;
mod rate_limit;
mod secondary_storage;
mod service;
#[cfg(feature = "axum")]
mod session_cache;
mod session_config;
mod siwe;
mod step_up;
mod store;
mod symmetric_crypto;
#[cfg(feature = "axum")]
mod symmetric_jwe;
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
    AdminListUsersQuery, AdminPermissionSet, AdminPlugin, AdminRole, AdminSortDirection,
    AdminUserUpdate,
};
pub use anonymous::{
    AnonymousEmailGenerator, AnonymousLinkAccount, AnonymousLinkAccountCallback,
    AnonymousNameGenerator, AnonymousPlugin, AnonymousPluginConfig, AnonymousSignInContext,
};
pub use api_key::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyExpirationConfig, ApiKeyGenerator, ApiKeyPlugin,
    ApiKeyRateLimitConfig, ApiKeyReference, ApiKeyStartingCharactersConfig,
};
pub use audit::{
    AUDIT_ACTION_VOCABULARY_VERSION, AuditEvent, AuditMetadata, AuditOutcome, AuditPlugin,
    AuditStore, MemoryAuditStore,
};
pub use bearer::{BearerConfig, BearerPlugin};
pub use breached_password::{PasswordBreachChecker, PwnedPasswordsChecker};
pub use client_ip::IpAddressConfig;
pub use config::{
    AccountConfig, AccountLinkingConfig, AuthConfig, EmailPasswordConfig, OAuthStateStrategy,
    VerificationConfig, VerificationIdentifierConfig, VerificationIdentifierHasher,
    VerificationIdentifierStorage, VersionedSecret,
};
pub use cookie::{CookieAttributes, CookieConfig, CookieOptions, SameSite};
pub use database_hooks::{
    BeforeDatabaseHook, DatabaseHookContext, DatabaseHookRequest, DatabaseHooks, DatabaseModel,
    DatabaseRecord,
};
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
pub use error::AuthError;
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
pub use memory::MemoryStore;
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
    OrganizationStore, OrganizationTeam, OrganizationTeamMember, OrganizationTeamStore,
    OrganizationTeamWriteOutcome, OrganizationTeamsConfig, OrganizationUpdate,
};
pub use origin::TrustedOrigin;
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
    AfterAuthEvent, AuthPlugin, BeforeAuthEvent, PasswordCredentialChanged,
    PasswordCredentialSource, PluginClientMetadata, PluginCookie, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginMiddleware, PluginMigration, PluginMigrationContribution,
    PluginRateLimit, PluginSchemaField, SensitiveOperation, UserManagementAction,
    UserManagementDecision, UserManagementOperation,
};
#[cfg(feature = "axum")]
pub use plugin::{AxumPluginRoute, PluginRequestContext, PluginSession};
pub use rate_limit::{
    RateLimitConfig, RateLimitCustomRule, RateLimitOutcome, RateLimitRequest, RateLimitRule,
    RateLimitRuleResolver, RateLimitStorage, RateLimitStorageMode,
};
pub use secondary_storage::{MemorySecondaryStorage, SecondaryStorage};
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
    EmailVerificationOutcome, OAuthAccountOwner, OAuthAccountStore, OAuthTokenUpdateOutcome,
    PasskeyDeleteOutcome, PasswordResetOutcome, SecurityStore, UserProfileUpdate,
    VerificationStore,
};
pub use two_factor::{
    AccountLockoutConfig, BackupCodeConfig, MemoryTwoFactorStore, OtpConfig, TotpConfig,
    TwoFactorConfig, TwoFactorError, TwoFactorOtp, TwoFactorOtpSender, TwoFactorPlugin,
    TwoFactorRecord, TwoFactorStore,
};
pub use user_deletion::{
    ChangeEmailConfig, ChangeEmailConfirmation, ChangeEmailConfirmationSender,
    DeleteAccountVerification, DeleteAccountVerificationSender, DeleteUserConfig, UserConfig,
    UserDeletionCallback,
};
pub use username::{
    UsernameConfig, UsernameError, UsernameNormalizer, UsernamePlugin, UsernameValidationOrder,
    UsernameValidationTiming, UsernameValidator,
};
