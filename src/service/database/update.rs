use crate::{AuthError, BeforeDatabaseUpdateHook, DatabaseRecord, DatabaseUpdateRecord};

pub(super) fn apply_before(
    result: BeforeDatabaseUpdateHook,
    current: &mut DatabaseUpdateRecord,
) -> Result<(), AuthError> {
    match result {
        BeforeDatabaseUpdateHook::Continue => Ok(()),
        BeforeDatabaseUpdateHook::Merge(patch) => {
            current.merge(patch);
            Ok(())
        }
        BeforeDatabaseUpdateHook::Cancel => Err(AuthError::DatabaseHookCancelled {
            model: current.model().as_str(),
            operation: "update",
        }),
    }
}

pub(super) fn cancelled(record: &DatabaseRecord, operation: &'static str) -> AuthError {
    AuthError::DatabaseHookCancelled {
        model: record.model().as_str(),
        operation,
    }
}
