mod data;
mod invitation;
mod member;
mod role;
mod rows;
mod team;

#[cfg(test)]
mod test_support;

use crate::AuthError;

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
