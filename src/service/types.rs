use crate::SessionWithUser;

#[derive(Debug, Clone)]
pub struct SignInResult {
    pub token: String,
    pub session: SessionWithUser,
}

/// Closed-registration account provisioned from an existing Argon2 password hash.
#[derive(Debug, Clone)]
pub struct HashedPasswordUser {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: String,
}
