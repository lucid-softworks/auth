use super::{SCIM_ENTERPRISE_USER_SCHEMA, SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA};
use serde_json::{Value, json};

const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SERVICE_PROVIDER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

pub(super) fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": [SERVICE_PROVIDER_SCHEMA],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 100 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "name": "OAuth Bearer Token",
            "description": "Authentication using a bearer token in the Authorization header.",
            "specUri": "https://www.rfc-editor.org/info/rfc6750",
            "type": "oauthbearertoken",
            "primary": true
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": absolute(base, "/scim/v2/ServiceProviderConfig")
        }
    })
}

pub(super) fn schemas(base: &str) -> Vec<Value> {
    vec![user_schema(base), enterprise_schema(base), group_schema(base)]
}

pub(super) fn resource_types(base: &str) -> Vec<Value> {
    vec![
        json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": SCIM_USER_SCHEMA,
            "schemaExtensions": [{ "schema": SCIM_ENTERPRISE_USER_SCHEMA, "required": false }],
            "meta": { "resourceType": "ResourceType", "location": absolute(base, "/scim/v2/ResourceTypes/User") }
        }),
        json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": SCIM_GROUP_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": absolute(base, "/scim/v2/ResourceTypes/Group") }
        }),
    ]
}

fn user_schema(base: &str) -> Value {
    json!({
        "id": SCIM_USER_SCHEMA,
        "schemas": [SCHEMA_SCHEMA],
        "name": "User",
        "description": "User Account",
        "attributes": [
            attribute("userName", "string", false, true, "server"),
            attribute("displayName", "string", false, false, "none"),
            attribute("active", "boolean", false, false, "none"),
            attribute("name", "complex", false, false, "none"),
            attribute("emails", "complex", true, false, "none"),
            attribute("title", "string", false, false, "none"),
            attribute("userType", "string", false, false, "none"),
            attribute("preferredLanguage", "string", false, false, "none"),
            attribute("locale", "string", false, false, "none"),
            attribute("timezone", "string", false, false, "none"),
            attribute("phoneNumbers", "complex", true, false, "none"),
            attribute("addresses", "complex", true, false, "none"),
            attribute("roles", "complex", true, false, "none"),
            attribute("entitlements", "complex", true, false, "none")
        ],
        "meta": { "resourceType": "Schema", "location": absolute(base, &format!("/scim/v2/Schemas/{SCIM_USER_SCHEMA}")) }
    })
}

fn enterprise_schema(base: &str) -> Value {
    json!({
        "id": SCIM_ENTERPRISE_USER_SCHEMA,
        "schemas": [SCHEMA_SCHEMA],
        "name": "EnterpriseUser",
        "description": "Enterprise User",
        "attributes": [
            attribute("employeeNumber", "string", false, false, "none"),
            attribute("costCenter", "string", false, false, "none"),
            attribute("organization", "string", false, false, "none"),
            attribute("division", "string", false, false, "none"),
            attribute("department", "string", false, false, "none"),
            attribute("manager", "complex", false, false, "none")
        ],
        "meta": { "resourceType": "Schema", "location": absolute(base, &format!("/scim/v2/Schemas/{SCIM_ENTERPRISE_USER_SCHEMA}")) }
    })
}

fn group_schema(base: &str) -> Value {
    json!({
        "id": SCIM_GROUP_SCHEMA,
        "schemas": [SCHEMA_SCHEMA],
        "name": "Group",
        "description": "Group",
        "attributes": [
            attribute("displayName", "string", false, true, "server"),
            attribute("members", "complex", true, false, "none")
        ],
        "meta": { "resourceType": "Schema", "location": absolute(base, &format!("/scim/v2/Schemas/{SCIM_GROUP_SCHEMA}")) }
    })
}

fn attribute(
    name: &str,
    kind: &str,
    multi_valued: bool,
    required: bool,
    uniqueness: &str,
) -> Value {
    json!({
        "name": name,
        "type": kind,
        "multiValued": multi_valued,
        "required": required,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": uniqueness,
        "caseExact": false
    })
}

pub(super) fn absolute(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}
