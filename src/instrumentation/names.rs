use super::{
    ATTR_CONTEXT, ATTR_DB_COLLECTION_NAME, ATTR_DB_OPERATION_NAME, ATTR_HOOK_TYPE, ATTR_HTTP_ROUTE,
    ATTR_OPERATION_ID, SpanAttribute,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterOperation {
    Create,
    FindOne,
    FindMany,
    Update,
    UpdateMany,
    Delete,
    DeleteMany,
    ConsumeOne,
    IncrementOne,
    Count,
}

impl AdapterOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::FindOne => "findOne",
            Self::FindMany => "findMany",
            Self::Update => "update",
            Self::UpdateMany => "updateMany",
            Self::Delete => "delete",
            Self::DeleteMany => "deleteMany",
            Self::ConsumeOne => "consumeOne",
            Self::IncrementOne => "incrementOne",
            Self::Count => "count",
        }
    }

    pub fn span(self, model: &str) -> (String, [SpanAttribute; 2]) {
        (
            format!("db {} {model}", self.as_str()),
            [
                SpanAttribute::string(ATTR_DB_OPERATION_NAME, self.as_str()),
                SpanAttribute::string(ATTR_DB_COLLECTION_NAME, model),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseHookOperation {
    CreateBefore,
    CreateAfter,
    UpdateBefore,
    UpdateAfter,
    UpdateManyBefore,
    UpdateManyAfter,
    DeleteBefore,
    DeleteAfter,
}

impl DatabaseHookOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateBefore => "create.before",
            Self::CreateAfter => "create.after",
            Self::UpdateBefore => "update.before",
            Self::UpdateAfter => "update.after",
            Self::UpdateManyBefore => "updateMany.before",
            Self::UpdateManyAfter => "updateMany.after",
            Self::DeleteBefore => "delete.before",
            Self::DeleteAfter => "delete.after",
        }
    }

    pub fn span(self, model: &str, source: HookSource<'_>) -> (String, [SpanAttribute; 3]) {
        (
            format!("db {} {model}", self.as_str()),
            [
                SpanAttribute::string(ATTR_HOOK_TYPE, self.as_str()),
                SpanAttribute::string(ATTR_DB_COLLECTION_NAME, model),
                SpanAttribute::string(ATTR_CONTEXT, source.as_str()),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSource<'a> {
    User,
    Plugin(&'a str),
}

impl HookSource<'_> {
    pub fn as_str(self) -> String {
        match self {
            Self::User => "user".into(),
            Self::Plugin(id) => format!("plugin:{id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSpanMetadata {
    pub method: String,
    pub route: String,
    pub operation_id: String,
}

impl EndpointSpanMetadata {
    pub fn new(
        method: impl Into<String>,
        route: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            route: route.into(),
            operation_id: operation_id.into(),
        }
    }

    pub fn dispatch_span(&self) -> (String, [SpanAttribute; 2]) {
        (format!("{} {}", self.method, self.route), self.attributes())
    }

    pub fn handler_span(&self) -> (String, [SpanAttribute; 2]) {
        (format!("handler {}", self.route), self.attributes())
    }

    pub fn hook_span(
        &self,
        hook_type: &'static str,
        source: HookSource<'_>,
    ) -> (String, [SpanAttribute; 4]) {
        let source = source.as_str();
        (
            format!("hook {hook_type} {} {source}", self.route),
            [
                SpanAttribute::string(ATTR_HOOK_TYPE, hook_type),
                SpanAttribute::string(ATTR_CONTEXT, source),
                SpanAttribute::string(ATTR_HTTP_ROUTE, self.route.clone()),
                SpanAttribute::string(ATTR_OPERATION_ID, self.operation_id.clone()),
            ],
        )
    }

    fn attributes(&self) -> [SpanAttribute; 2] {
        [
            SpanAttribute::string(ATTR_HTTP_ROUTE, self.route.clone()),
            SpanAttribute::string(ATTR_OPERATION_ID, self.operation_id.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_vocabulary_is_exact() {
        assert_eq!(
            [
                AdapterOperation::Create,
                AdapterOperation::FindOne,
                AdapterOperation::FindMany,
                AdapterOperation::Update,
                AdapterOperation::UpdateMany,
                AdapterOperation::Delete,
                AdapterOperation::DeleteMany,
                AdapterOperation::ConsumeOne,
                AdapterOperation::IncrementOne,
                AdapterOperation::Count,
            ]
            .map(AdapterOperation::as_str),
            [
                "create",
                "findOne",
                "findMany",
                "update",
                "updateMany",
                "delete",
                "deleteMany",
                "consumeOne",
                "incrementOne",
                "count",
            ]
        );
    }

    #[test]
    fn endpoint_names_and_attributes_match_better_auth() {
        let endpoint = EndpointSpanMetadata::new("POST", "/sign-in/email", "signInEmail");
        assert_eq!(endpoint.dispatch_span().0, "POST /sign-in/email");
        assert_eq!(endpoint.handler_span().0, "handler /sign-in/email");
        assert_eq!(
            endpoint.hook_span("before", HookSource::Plugin("guard")).0,
            "hook before /sign-in/email plugin:guard"
        );
    }
}
