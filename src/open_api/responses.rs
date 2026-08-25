use super::{OpenApiMediaType, OpenApiResponse};
use serde_json::json;
use std::collections::BTreeMap;

pub(super) fn standard_responses(
    overrides: &BTreeMap<String, OpenApiResponse>,
) -> BTreeMap<String, OpenApiResponse> {
    let mut responses = BTreeMap::from([
        (
            "400".into(),
            error_response(
                "Bad Request. Usually due to missing parameters, or invalid parameters.",
                true,
            ),
        ),
        (
            "401".into(),
            error_response(
                "Unauthorized. Due to missing or invalid authentication.",
                true,
            ),
        ),
        (
            "403".into(),
            error_response(
                "Forbidden. You do not have permission to access this resource or to perform this action.",
                false,
            ),
        ),
        (
            "404".into(),
            error_response("Not Found. The requested resource was not found.", false),
        ),
        (
            "429".into(),
            error_response(
                "Too Many Requests. You have exceeded the rate limit. Try again later.",
                false,
            ),
        ),
        (
            "500".into(),
            error_response(
                "Internal Server Error. This is a problem with the server that you cannot fix.",
                false,
            ),
        ),
    ]);
    responses.extend(overrides.clone());
    responses
}

fn error_response(description: &str, required: bool) -> OpenApiResponse {
    OpenApiResponse {
        description: description.into(),
        content: Some(BTreeMap::from([(
            "application/json".into(),
            OpenApiMediaType {
                schema: if required {
                    json!({
                        "type": "object",
                        "properties": { "message": { "type": "string" } },
                        "required": ["message"],
                    })
                } else {
                    json!({
                        "type": "object",
                        "properties": { "message": { "type": "string" } },
                    })
                },
                extensions: BTreeMap::new(),
            },
        )])),
        extensions: BTreeMap::new(),
    }
}
