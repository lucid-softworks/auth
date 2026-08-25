mod fields;
mod generator;
mod responses;
mod schema;
mod types;

#[cfg(feature = "axum")]
mod axum;
mod plugin;

pub use generator::generate_open_api_schema;
pub use plugin::{OpenApiConfig, OpenApiPlugin, OpenApiTheme};
pub(crate) use types::endpoints_from_descriptor;
pub use types::{
    FieldSchema, FieldSchemaKind, OpenApiComponents, OpenApiEndpoint, OpenApiInfo,
    OpenApiMediaType, OpenApiModel, OpenApiModelSchema, OpenApiOperation, OpenApiParameter,
    OpenApiPath, OpenApiRequestBody, OpenApiResponse, OpenApiSchema, OpenApiServer, OpenApiTag,
};
