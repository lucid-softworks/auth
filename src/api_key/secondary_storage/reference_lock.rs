use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

type LockRegistry = Mutex<HashMap<String, Weak<Mutex<()>>>>;

fn registry() -> &'static LockRegistry {
    static REGISTRY: OnceLock<LockRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) async fn acquire(reference_key: &str) -> OwnedMutexGuard<()> {
    let lock = {
        let mut registry = registry().lock().await;
        registry.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = registry.get(reference_key).and_then(Weak::upgrade) {
            lock
        } else {
            let lock = Arc::new(Mutex::new(()));
            registry.insert(reference_key.to_owned(), Arc::downgrade(&lock));
            lock
        }
    };
    lock.lock_owned().await
}
