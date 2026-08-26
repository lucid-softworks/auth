use crate::{
    AuthenticationMethod, TestCookie, TestHelpers, TestLoginResult, TestUtilsError,
    cookie::CookieKind,
};
use chrono::Utc;
use std::collections::BTreeMap;
use uuid::Uuid;

impl TestHelpers<'_> {
    pub async fn login(&self, user_id: Uuid) -> Result<TestLoginResult, TestUtilsError> {
        let (token, session, user) = self.create_test_session(user_id).await?;
        Ok(TestLoginResult {
            headers: cookie_headers(self.service, &token),
            cookies: test_cookies(self.service, &token, None),
            token,
            session,
            user,
        })
    }

    pub async fn get_auth_headers(
        &self,
        user_id: Uuid,
    ) -> Result<BTreeMap<String, String>, TestUtilsError> {
        let (token, _, _) = self.create_test_session(user_id).await?;
        Ok(cookie_headers(self.service, &token))
    }

    pub async fn get_cookies(
        &self,
        user_id: Uuid,
        domain: Option<&str>,
    ) -> Result<Vec<TestCookie>, TestUtilsError> {
        let (token, _, _) = self.create_test_session(user_id).await?;
        Ok(test_cookies(self.service, &token, domain))
    }

    async fn create_test_session(
        &self,
        user_id: Uuid,
    ) -> Result<(String, crate::AuthSession, crate::AuthUser), TestUtilsError> {
        let user = self
            .service
            .store
            .find_user_by_id(&user_id.to_string())
            .await?
            .ok_or(TestUtilsError::UserNotFound(user_id))?;
        let result = self
            .service
            .create_session(user, AuthenticationMethod::Extension, None, None, None)
            .await?;
        Ok((result.token, result.session.session, result.session.user))
    }
}

fn cookie_headers(service: &crate::AuthService, token: &str) -> BTreeMap<String, String> {
    let cookie = service.config.cookies.resolve(
        CookieKind::SessionToken,
        service.cookie_secure(),
        service
            .config
            .base_url
            .as_ref()
            .and_then(url::Url::host_str),
    );
    BTreeMap::from([(
        "cookie".into(),
        format!("{}={}", cookie.name, service.raw_signed_cookie_value(token)),
    )])
}

fn test_cookies(
    service: &crate::AuthService,
    token: &str,
    domain: Option<&str>,
) -> Vec<TestCookie> {
    let base_host = service
        .config
        .base_url
        .as_ref()
        .and_then(url::Url::host_str);
    let cookie = service.config.cookies.resolve(
        CookieKind::SessionToken,
        service.cookie_secure(),
        base_host,
    );
    let max_age = cookie
        .attributes
        .max_age
        .or_else(|| Some(service.config.session_ttl.num_seconds() as f64));
    vec![TestCookie {
        name: cookie.name,
        value: service.raw_signed_cookie_value(token),
        domain: domain.or(base_host).unwrap_or("localhost").to_owned(),
        path: cookie.attributes.path,
        http_only: cookie.attributes.http_only,
        secure: cookie.attributes.secure,
        same_site: cookie.attributes.same_site.as_str().into(),
        expires: max_age
            .filter(|max_age| *max_age != 0.0)
            .map(|max_age| Utc::now().timestamp() + max_age.floor() as i64),
    }]
}
