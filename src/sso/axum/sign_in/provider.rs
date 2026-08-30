use super::{SignInBody, support};
use crate::{AuthService, SsoPlugin, SsoProvider};
use axum::response::Response;
use url::Url;

pub(super) async fn resolve(
    service: &AuthService,
    plugin: &SsoPlugin,
    body: &SignInBody,
) -> Result<SsoProvider, Box<Response>> {
    if body.email.is_none()
        && body.organization_slug.is_none()
        && body.domain.is_none()
        && body.provider_id.is_none()
    {
        return Err(Box::new(support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "email, organizationSlug, domain or providerId is required",
        )));
    }
    let domain = body.domain.as_deref().or_else(|| {
        body.email
            .as_deref()
            .and_then(|email| email.split('@').nth(1))
    });
    let organization_id = match body.organization_slug.as_deref() {
        Some(slug) => match service.organization_plugin() {
            Ok(organization) => organization
                .store
                .find_organization_by_slug(slug)
                .await
                .ok()
                .flatten()
                .map(|organization| organization.id),
            Err(_) => None,
        },
        None => None,
    };
    if body.provider_id.is_none() && organization_id.is_none() && domain.is_none() {
        return Err(Box::new(support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "providerId, orgId or domain is required",
        )));
    }
    let provider = if let Some(provider_id) = body.provider_id.as_deref() {
        plugin.store().find_by_provider_id(provider_id).await
    } else {
        let providers = plugin.store().list().await;
        providers.map(|providers| {
            if let Some(organization_id) = organization_id.as_deref() {
                providers
                    .into_iter()
                    .find(|provider| provider.organization_id.as_deref() == Some(organization_id))
            } else {
                let domain = domain.expect("provider selector exists");
                providers
                    .iter()
                    .find(|provider| provider.domain == domain)
                    .cloned()
                    .or_else(|| {
                        providers
                            .into_iter()
                            .find(|provider| domain_matches(domain, &provider.domain))
                    })
            }
        })
    }
    .map_err(|error| Box::new(support::storage(error)))?;
    provider.ok_or_else(|| {
        Box::new(support::error(
            axum::http::StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "No provider found for the issuer",
        ))
    })
}

fn domain_matches(search: &str, configured: &str) -> bool {
    let search = search.trim().to_lowercase();
    !search.is_empty()
        && configured.split(',').filter_map(hostname).any(|domain| {
            search == domain || search.ends_with(&format!(".{domain}"))
        })
}

fn hostname(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .or_else(|| {
            Url::parse(&format!("https://{value}"))
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        })
        .map(|hostname| hostname.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching_supports_lists_subdomains_and_url_shaped_values() {
        assert!(domain_matches(
            "login.staff.example.com",
            "https://example.org/path, EXAMPLE.com"
        ));
        assert!(!domain_matches("notexample.com", "example.com"));
    }
}
