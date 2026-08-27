use reqwest::Method;

const GET_ROUTES: &[&str] = &[
    "/callback/:id",
    "/oauth2/callback/:providerId",
    "/dash/impersonate-user",
    "/verify-email",
    "/magic-link/verify",
    "/dash/accept-invitation",
    "/dash/complete-invitation-social",
];

pub(super) fn should_run(method: &Method, path: &str) -> bool {
    method != Method::GET || GET_ROUTES.iter().any(|route| matches(path, route))
}

pub(super) fn is_dash_route(path: &str) -> bool {
    matches(path, "/dash")
}

fn matches(path: &str, route: &str) -> bool {
    let path = strip_query(path);
    let route = strip_query(route);
    let path_parts = path.split('/').collect::<Vec<_>>();
    let route_parts = route.split('/').collect::<Vec<_>>();
    if path_parts.len() < route_parts.len() {
        return false;
    }
    if !path_parts
        .iter()
        .zip(&route_parts)
        .all(|(actual, expected)| {
            (expected.starts_with(':') && !actual.is_empty()) || actual == expected
        })
    {
        return false;
    }
    true
}

fn strip_query(value: &str) -> &str {
    value
        .split('?')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_templates_use_the_published_prefix_boundary() {
        assert!(should_run(&Method::GET, "/callback/github"));
        assert!(should_run(&Method::GET, "/callback/github/extra"));
        assert!(should_run(&Method::GET, "/verify-email?token=x"));
        assert!(!should_run(&Method::GET, "/verify-emailish"));
        assert!(!should_run(&Method::GET, "/session"));
        assert!(should_run(&Method::POST, "/session"));
        assert!(is_dash_route("/dash"));
        assert!(is_dash_route("/dash/users"));
        assert!(!is_dash_route("/dashboard"));
    }
}
