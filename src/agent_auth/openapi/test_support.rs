use serde_json::{Value, json};

pub(super) fn fixture() -> Value {
    json!({
        "info": {"title":"Message API","description":"Read and create messages"},
        "components": {"parameters": {"messageId": {
            "name":"id","in":"path","required":true,"description":"Message identifier",
            "schema":{"type":"string"}
        }}},
        "paths": {"/messages/{id}": {
            "parameters":[{"$ref":"#/components/parameters/messageId"}],
            "get": {
                "operationId":"messages.get","summary":"Get a message",
                "parameters":[
                    {"name":"verbose","in":"query","schema":{"type":"boolean"}},
                    {"name":"x-tenant","in":"header","required":true}
                ],
                "responses":{"200":{"content":{"application/json":{"schema":{
                    "type":"object","properties":{"id":{"type":"string"}}
                }}}}}
            },
            "post": {
                "operationId":"messages.create","description":"Create a message",
                "requestBody":{"required":true,"content":{"application/json":{"schema":{
                    "type":"object","properties":{"subject":{"type":"string"}},
                    "required":["subject"]
                }}}},
                "responses":{"201":{"description":"Created"}}
            }
        }}
    })
}
