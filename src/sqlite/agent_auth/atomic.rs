use super::record;
use crate::{
    AgentAuthStore, AgentCapabilityTransitionOutcome, AgentCapabilityTransitionPlan, AuthError,
    sqlite::SqliteStore,
};

pub(super) async fn transition(
    store: &SqliteStore,
    plan: AgentCapabilityTransitionPlan,
) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
    let plan = record::normalize_plan(plan);
    let mut connection = record::begin_immediate(store).await?;
    let work = async {
        let before = record::load_snapshot(store, &mut connection).await?;
        let memory = crate::MemoryAgentAuthStore::from_snapshot(before.clone());
        let result = memory
            .request_capabilities_atomic(crate::AgentRequestCapabilitiesTransition(plan))
            .await?;
        let after = memory.snapshot()?;
        record::sync_snapshot(store, &mut connection, &before, &after).await?;
        Ok::<_, AuthError>(result)
    }
    .await;
    match work {
        Ok(result) => match record::commit(&mut connection).await {
            Ok(()) => Ok(result),
            Err(error) => {
                record::rollback(&mut connection).await;
                Err(error)
            }
        },
        Err(error) => {
            record::rollback(&mut connection).await;
            Err(error)
        }
    }
}
