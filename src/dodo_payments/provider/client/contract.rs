use super::*;
use crate::dodo_payments::transport::DodoPaymentsTransportRequest;
use std::{collections::VecDeque, sync::Mutex};

struct RecordingTransport {
    requests: Mutex<Vec<DodoPaymentsTransportRequest>>,
    responses: Mutex<VecDeque<Value>>,
}

impl RecordingTransport {
    fn new(responses: impl IntoIterator<Item = Value>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }

    fn requests(&self) -> Vec<DodoPaymentsTransportRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl DodoPaymentsTransport for RecordingTransport {
    fn environment(&self) -> DodoPaymentsEnvironment {
        DodoPaymentsEnvironment::Test
    }

    async fn send(
        &self,
        request: DodoPaymentsTransportRequest,
    ) -> Result<Value, DodoPaymentsProviderError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| DodoPaymentsProviderError::new("missing test response"))
    }
}

#[path = "contract/commerce.rs"]
mod commerce;
#[path = "contract/customer.rs"]
mod customer;
#[path = "contract/lists.rs"]
mod lists;
