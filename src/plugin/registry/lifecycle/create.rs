use super::super::PluginRegistry;
use crate::{AuthError, BeforeDatabaseCreateHook, DatabaseCreateRecord, DatabaseHookContext};

impl PluginRegistry {
    pub(crate) async fn before_database_create(
        &self,
        mut record: DatabaseCreateRecord,
        context: &DatabaseHookContext,
    ) -> Result<DatabaseCreateRecord, AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            apply_before(hooks.before_create(&record, context).await?, &mut record)?;
        }
        Ok(record)
    }
}

fn apply_before(
    result: BeforeDatabaseCreateHook,
    current: &mut DatabaseCreateRecord,
) -> Result<(), AuthError> {
    match result {
        BeforeDatabaseCreateHook::Continue => Ok(()),
        BeforeDatabaseCreateHook::Merge(patch) => {
            current.merge(patch);
            Ok(())
        }
        BeforeDatabaseCreateHook::Cancel => Err(AuthError::DatabaseHookCancelled {
            model: current.model().as_str(),
            operation: "create",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, AuthPlugin, DatabaseCreatePatch, DatabaseHooks, DatabaseIdInput, DatabaseModel,
        PluginDescriptor, PluginProvenance, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
    };
    use async_trait::async_trait;
    use serde_json::{Map, json};
    use std::{
        borrow::Cow,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    struct RecordingCreateHooks {
        seen: Arc<Mutex<Vec<DatabaseCreateRecord>>>,
        calls: Arc<AtomicUsize>,
        result: BeforeDatabaseCreateHook,
    }

    #[async_trait]
    impl DatabaseHooks for RecordingCreateHooks {
        async fn before_create(
            &self,
            record: &DatabaseCreateRecord,
            _context: &DatabaseHookContext,
        ) -> Result<BeforeDatabaseCreateHook, AuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock()
                .expect("recording hook lock is not poisoned")
                .push(record.clone());
            Ok(self.result.clone())
        }
    }

    struct HookPlugin {
        id: &'static str,
        hooks: RecordingCreateHooks,
    }

    #[async_trait]
    impl AuthPlugin for HookPlugin {
        fn descriptor(&self) -> PluginDescriptor {
            PluginDescriptor {
                id: self.id,
                display_name: "Create hook fixture",
                version: COMPATIBLE_BETTER_AUTH_VERSION,
                provenance: PluginProvenance::lucid_extension(),
                dependencies: &[],
                conflicts: &[],
                endpoints: Cow::Borrowed(&[]),
                cookies: &[],
                rate_limits: &[],
                middleware: &[],
                client: None,
            }
        }

        fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
            Some(&self.hooks)
        }
    }

    fn plugin(
        id: &'static str,
        seen: Arc<Mutex<Vec<DatabaseCreateRecord>>>,
        calls: Arc<AtomicUsize>,
        result: BeforeDatabaseCreateHook,
    ) -> Arc<dyn AuthPlugin> {
        Arc::new(HookPlugin {
            id,
            hooks: RecordingCreateHooks {
                seen,
                calls,
                result,
            },
        })
    }

    #[tokio::test]
    async fn hooks_observe_and_shallow_merge_accumulated_patches_in_order() {
        let first_seen = Arc::new(Mutex::new(Vec::new()));
        let second_seen = Arc::new(Mutex::new(Vec::new()));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let plugins = vec![
            plugin(
                "first-create-hook",
                first_seen.clone(),
                first_calls.clone(),
                BeforeDatabaseCreateHook::merge(
                    DatabaseCreatePatch::new()
                        .with_id(DatabaseIdInput::String("first-id".into()))
                        .with_field("name", json!("first"))
                        .with_field("metadata", json!({ "first": true, "shared": true })),
                ),
            ),
            plugin(
                "second-create-hook",
                second_seen.clone(),
                second_calls.clone(),
                BeforeDatabaseCreateHook::merge(
                    DatabaseCreatePatch::new()
                        .with_field("email", json!("hook@example.com"))
                        .with_field("metadata", json!({ "second": true })),
                ),
            ),
        ];
        let registry = PluginRegistry::build(&plugins, &AuthConfig::new([7; 32]).unwrap()).unwrap();

        let output = registry
            .before_database_create(
                DatabaseCreateRecord::new(
                    DatabaseModel::User,
                    Map::from_iter([("name".into(), json!("initial"))]),
                ),
                &DatabaseHookContext::default(),
            )
            .await
            .unwrap();

        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first_seen.lock().unwrap()[0].id(), &DatabaseIdInput::Absent);
        let second_records = second_seen.lock().unwrap();
        let second_input = &second_records[0];
        assert_eq!(
            second_input.id(),
            &DatabaseIdInput::String("first-id".into())
        );
        assert_eq!(second_input.get("name"), Some(&json!("first")));
        assert_eq!(output.id(), &DatabaseIdInput::String("first-id".into()));
        assert_eq!(output.get("email"), Some(&json!("hook@example.com")));
        assert_eq!(output.get("metadata"), Some(&json!({ "second": true })));
    }

    #[tokio::test]
    async fn cancel_stops_later_hook_dispatch() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let plugins = vec![
            plugin(
                "cancelling-create-hook",
                Arc::new(Mutex::new(Vec::new())),
                first_calls.clone(),
                BeforeDatabaseCreateHook::Cancel,
            ),
            plugin(
                "unreached-create-hook",
                Arc::new(Mutex::new(Vec::new())),
                second_calls.clone(),
                BeforeDatabaseCreateHook::Continue,
            ),
        ];
        let registry = PluginRegistry::build(&plugins, &AuthConfig::new([8; 32]).unwrap()).unwrap();

        let error = registry
            .before_database_create(
                DatabaseCreateRecord::new(DatabaseModel::Session, Map::new()),
                &DatabaseHookContext::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            AuthError::DatabaseHookCancelled {
                model: "session",
                operation: "create"
            }
        ));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    }
}
