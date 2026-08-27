use lucid_auth::{
    DatabaseIdGenerationRequest, DatabaseIdGenerationResult, DatabaseIdGenerationSize,
    DatabaseIdGenerator,
};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct CallbackCall {
    pub(super) model: String,
    pub(super) size: DatabaseIdGenerationSize,
}

#[derive(Debug, Default)]
pub(super) struct CallbackLedger {
    calls: Mutex<Vec<CallbackCall>>,
}

impl CallbackLedger {
    pub(super) fn snapshot(&self) -> Vec<CallbackCall> {
        self.calls.lock().unwrap().clone()
    }

    pub(super) fn count_model(&self, model: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.model == model)
            .count()
    }
}

impl DatabaseIdGenerator for CallbackLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let mut calls = self.calls.lock().unwrap();
        calls.push(CallbackCall {
            model: request.model.to_owned(),
            size: request.size,
        });
        DatabaseIdGenerationResult::Id(format!("callback/{}/{}", request.model, calls.len()))
    }
}

pub(super) fn expected(model: &str) -> CallbackCall {
    CallbackCall {
        model: model.into(),
        size: DatabaseIdGenerationSize::Omitted,
    }
}
