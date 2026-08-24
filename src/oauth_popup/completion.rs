use super::{OAUTH_POPUP_DATA_ELEMENT_ID, OAUTH_POPUP_MESSAGE_TYPE, OAUTH_POPUP_SCRIPT_CSP_HASH};
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use serde_json::Value;

pub(super) const OAUTH_POPUP_COMPLETE_SCRIPT: &str = r#"(function () {
	var el = document.getElementById("better-auth-oauth-popup");
	if (!el) return;
	var payload;
	try {
		payload = JSON.parse(el.textContent || "");
	} catch (e) {
		return;
	}
	var target = window.opener || window.parent;
	if (target && target !== window) {
		try {
			target.postMessage(
				{
					type: payload.type,
					nonce: payload.nonce,
					token: payload.token,
					redirectTo: payload.redirectTo,
					error: payload.error,
				},
				payload.targetOrigin,
			);
		} catch (e) {}
	}
	window.close();
})();
"#;

pub(super) enum CompletionMessage {
    Success {
        nonce: Value,
        token: String,
        redirect_to: String,
    },
    Error {
        nonce: Value,
        code: String,
        description: Option<String>,
    },
}

pub(super) fn render(target_origin: Option<Value>, message: CompletionMessage) -> Response {
    let payload = inline_json(target_origin, message);
    let html = format!(
        "<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Completing sign-in</title></head>\n<body>\n<script type=\"application/json\" id=\"{OAUTH_POPUP_DATA_ELEMENT_ID}\">{payload}</script>\n<script>{OAUTH_POPUP_COMPLETE_SCRIPT}</script>\n</body>\n</html>"
    );
    let mut response = Response::new(Body::from(html));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!(
            "default-src 'none'; script-src '{OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'"
        ))
        .expect("the pinned popup CSP is a valid header"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn inline_json(target_origin: Option<Value>, message: CompletionMessage) -> String {
    let mut payload = String::from("{");
    payload.push_str("\"type\":");
    payload.push_str(&json_string(OAUTH_POPUP_MESSAGE_TYPE));
    if let Some(target_origin) = target_origin {
        payload.push_str(&format!(
            ",\"targetOrigin\":{}",
            serde_json::to_string(&target_origin).expect("JSON values serialize")
        ));
    }
    payload = match message {
        CompletionMessage::Success {
            nonce,
            token,
            redirect_to,
        } => success_json(payload, nonce, &token, &redirect_to),
        CompletionMessage::Error {
            nonce,
            code,
            description,
        } => error_json(payload, nonce, &code, description.as_deref()),
    };
    payload.push('}');
    escape_inline_json(payload)
}

fn success_json(mut payload: String, nonce: Value, token: &str, redirect_to: &str) -> String {
    payload.push_str(&format!(
        ",\"nonce\":{},\"token\":{},\"redirectTo\":{}",
        serde_json::to_string(&nonce).expect("JSON values serialize"),
        json_string(token),
        json_string(redirect_to)
    ));
    payload
}

fn error_json(mut payload: String, nonce: Value, code: &str, description: Option<&str>) -> String {
    payload.push_str(",\"nonce\":");
    payload.push_str(&serde_json::to_string(&nonce).expect("JSON values serialize"));
    payload.push_str(",\"error\":");
    payload.push('{');
    payload.push_str("\"code\":");
    payload.push_str(&json_string(code));
    if let Some(description) = description {
        payload.push_str(&format!(",\"description\":{}", json_string(description)));
    }
    payload.push('}');
    payload
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize")
}

fn escape_inline_json(value: String) -> String {
    value
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use http_body_util::BodyExt;
    use sha2::Digest as _;

    #[tokio::test]
    async fn page_and_json_escaping_are_pinned() {
        let digest = sha2::Sha256::digest(OAUTH_POPUP_COMPLETE_SCRIPT.as_bytes());
        assert_eq!(
            format!(
                "sha256-{}",
                base64::engine::general_purpose::STANDARD.encode(digest)
            ),
            OAUTH_POPUP_SCRIPT_CSP_HASH
        );
        let response = render(
            Some(Value::String("https://app.example/<\u{2028}".into())),
            CompletionMessage::Error {
                nonce: Value::String("n\u{2029}".into()),
                code: "broken".into(),
                description: None,
            },
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; script-src 'sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ='; base-uri 'none'"
        );
        let html = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("https://app.example/\\u003c\\u2028"));
        assert!(html.contains("n\\u2029"));
        assert!(html.contains(OAUTH_POPUP_COMPLETE_SCRIPT));
    }
}
