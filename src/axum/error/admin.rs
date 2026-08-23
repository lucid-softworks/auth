use axum::http::StatusCode;

pub(super) type Details = (StatusCode, &'static str, &'static str);

pub(super) fn details(error: crate::AdminError) -> Details {
    use crate::AdminError::*;
    match error {
        CannotCreateUsers => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
            "You are not allowed to create users",
        ),
        CannotListUsers => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
            "You are not allowed to list users",
        ),
        CannotGetUser => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
            "You are not allowed to get user",
        ),
        CannotUpdateUsers => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
            "You are not allowed to update users",
        ),
        CannotSetRole => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
            "You are not allowed to change users role",
        ),
        CannotBanUsers => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
            "You are not allowed to ban users",
        ),
        CannotImpersonateUsers => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
            "You are not allowed to impersonate users",
        ),
        CannotDeleteUsers => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
            "You are not allowed to delete users",
        ),
        CannotSetPassword => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
            "You are not allowed to set users password",
        ),
        CannotSetEmail => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL",
            "You are not allowed to update users email",
        ),
        CannotListSessions => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS",
            "You are not allowed to list users sessions",
        ),
        CannotRevokeSessions => forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
            "You are not allowed to revoke users sessions",
        ),
        RoleNotFound => bad_request(
            "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
            "You are not allowed to set a non-existent role value",
        ),
        InvalidRoleType => bad_request("INVALID_ROLE_TYPE", "Invalid role type"),
        CannotBanSelf => bad_request("YOU_CANNOT_BAN_YOURSELF", "You cannot ban yourself"),
        CannotRemoveSelf => bad_request("YOU_CANNOT_REMOVE_YOURSELF", "You cannot remove yourself"),
        CannotImpersonateAdmin => forbidden(
            "YOU_CANNOT_IMPERSONATE_ADMINS",
            "You cannot impersonate admins",
        ),
        NoDataToUpdate => bad_request("NO_DATA_TO_UPDATE", "No data to update"),
        PasswordUpdateForbidden => bad_request(
            "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
            "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
        ),
        UserNotFound => (StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found"),
        UserAlreadyExistsEmail => bad_request(
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
            "User already exists. Use another email.",
        ),
    }
}

fn forbidden(code: &'static str, message: &'static str) -> Details {
    (StatusCode::FORBIDDEN, code, message)
}

fn bad_request(code: &'static str, message: &'static str) -> Details {
    (StatusCode::BAD_REQUEST, code, message)
}
