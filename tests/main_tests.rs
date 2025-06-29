// Update the import paths to point to the correct locations, e.g., use super:: if these modules are in the parent directory,
// or provide the correct relative path. If these modules do not exist, you need to create them or mock them for testing.

use super::auth::AuthSession;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{Key, SameSite},
    dev,
    dev::Service,
    http::{header, StatusCode},
    test, web, App, HttpMessage, HttpRequest, HttpResponse, Responder,
};
// Adjust the import path as needed; for example, if config.rs is in the parent directory:
use crate::{
    auth::AuthSession,
    config::Config,
    configure_app,
    security::{Nonce, SecurityHeaders},
};
use scraper::{Html, Selector};
use serde_json::Value;
use std::{str, time::Duration};
use tera::Tera;

async fn setup_test_app() -> Box<
    dyn Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
> {
    let config = Config::from_env().expect("Failed to load test config");
    let tera = Tera::new("templates/**/*").expect("Failed to init Tera");
    let session_key = Key::from(config.hmac_secret.as_bytes());
    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(config.rate_limit_per_second)
        .burst_size(config.rate_limit_burst_size)
        .finish()
        .unwrap();

    let session_middleware =
        SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
            .cookie_name("erp-session".to_string())
            .cookie_secure(false)
            .cookie_http_only(true)
            .cookie_same_site(SameSite::Strict)
            .session_lifecycle(PersistentSession::default().session_ttl(
                actix_web::cookie::time::Duration::seconds(config.session_max_age_seconds as i64),
            ))
            .build();

    Box::new(
        test::init_service(
            App::new()
                .app_data(web::Data::new(config.clone()))
                .app_data(web::Data::new(tera.clone()))
                .wrap(Governor::new(&governor_conf))
                .wrap(SecurityHeaders)
                .wrap(session_middleware)
                .configure(configure_app),
        )
        .await,
    )
}

fn extract_csrf_token(body: &str) -> String {
    let document = Html::parse_document(body);
    let selector = Selector::parse("input[name=\"csrf_token\"]").unwrap();
    document
        .select(&selector)
        .next()
        .and_then(|input| input.value().attr("value"))
        .unwrap_or_default()
        .to_string()
}

#[actix_web::test]
async fn test_unauthenticated_access_is_denied() {
    let app = setup_test_app().await;
    let req = test::TestRequest::get().uri("/").to_request();

    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");
}

#[actix_web::test]
async fn test_login_page_loads_with_headers_and_csrf() {
    let app = setup_test_app().await;
    let req = test::TestRequest::get().uri("/login").to_request();

    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    assert!(resp.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");

    let body = test::read_body(resp).await;
    let body_str = str::from_utf8(&body).unwrap();
    let csrf_token_from_html = extract_csrf_token(body_str);

    let req = test::TestRequest::get().uri("/login").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
