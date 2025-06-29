// Main application entrypoint.
// This file has been refactored to align with the security and resilience
// principles outlined in the project blueprint.

mod auth;
mod config;
mod errors;
mod security;

use actix_csrf::CsrfMiddleware;
use actix_files::Files; // Use the idiomatic static file server
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_csrf::extractor::CsrfToken;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{Key, SameSite},
    web, dev, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use rand::rngs::StdRng;
use rustls::{pki_types::PrivateKeyDer, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use tera::Tera;
use time::Duration;
use tracing::info;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use crate::auth::{login_post, AuthGuard, AuthSession};
use crate::config::Config;
use crate::errors::AppError;
use crate::security::{Nonce, SecurityHeaders};

// --- Handlers ---

/// Renders the main dashboard for authenticated users.
async fn index(
    tera: web::Data<Tera>,
    session: AuthSession,
    req: HttpRequest,
) -> Result<impl Responder, AppError> {
    let mut context = tera::Context::new();
    let username = session
        .get_username()
        .unwrap_or_else(|| "Guest".to_string());
    // Pass the CSP nonce to the template for inline script authorization
    let nonce = req
        .extensions()
        .get::<Nonce>()
        .map_or_else(String::new, |n| n.0.clone());
    context.insert("username", &username);
    context.insert("nonce", &nonce);
    let rendered = tera.render("dashboard.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Renders the login page.
async fn login_get(tera: web::Data<Tera>, req: HttpRequest) -> Result<impl Responder, AppError> {
    let mut context = tera::Context::new();
    context.insert("error", "");
    // Pass the CSP nonce to the template
    let nonce = req
        .extensions()
        .get::<Nonce>()
        .map_or_else(String::new, |n| n.0.clone());
    // Pass the CSRF token to the template for form submission.
    // We get a reference from the extensions, clone it, and then call `into_inner`
    // to get the owned String value of the token.
    let token = req.extensions().get::<CsrfToken>().map(|t| t.clone().into_inner()).unwrap_or_default();

    context.insert("nonce", &nonce);
    context.insert("csrf_token", &token);
    let rendered = tera.render("login.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Logs the user out by clearing their session.
async fn logout(session: AuthSession) -> Result<impl Responder, AppError> {
    session.logout();
    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/login"))
        .finish())
}

/// Configures the application routes and services.
/// This function is used by both the main application and the test suite to
/// ensure consistency and reduce code duplication, a key principle for maintainability.
fn configure_app(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            // Protect the dashboard so only authenticated users can see it.
            .service(web::resource("/").guard(AuthGuard).to(index))
            // Protect logout so only authenticated users can attempt it.
            .service(web::resource("/logout").guard(AuthGuard).post(logout))
            // Apply CSRF middleware only to the login scope
            .service(
                web::scope("/login")
                    .wrap(CsrfMiddleware::<StdRng>::new())
                    .service(
                        web::resource("").route(web::get().to(login_get)).route(web::post().to(login_post)),
                    ),
            ),
    )
    // Serve static files from the "static" directory, as described in README.md
    .service(Files::new("/static", "./static"));
}
// --- Main Application Setup ---

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup modern logging with `tracing`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // 2. Load configuration from .env file
    let config = Config::from_env()?;

    // 3. Load TLS configuration, returning an error on failure instead of panicking.
    let tls_config = load_rustls_config()?;

    // 4. Configure rate limiting with `actix-governor`

    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(config.rate_limit_per_second)
        .burst_size(config.rate_limit_burst_size)
        .finish()
        .ok_or("Failed to build governor config")?;

    // 5. Initialize template engine, returning an error on failure.
    let tera = Tera::new("templates/**/*")?;

    // 6. Create the session key from the secret in config.
    let session_key = Key::from(config.hmac_secret.as_bytes());

    let app_config = config.clone();
    info!("Starting server at https://{}:{}", config.host, config.port);

    HttpServer::new(move || {
        // The `move` closure captures the cloned `app_config`.
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                .cookie_name("erp-session".to_string())
                .cookie_secure(true)
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Strict)
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(Duration::seconds(config.session_max_age_seconds as i64)),
                )
                .build();

        App::new()
            .wrap(TracingLogger::default()) // TracingLogger must be wrapped on the App, not HttpServer
            .app_data(web::Data::new(app_config.clone()))
            .app_data(web::Data::new(tera.clone()))
            // Middlewares are wrapped in reverse order of execution:
            // 1. Rate Limiting -> 2. Security Headers -> 3. Session
            .wrap(Governor::new(&governor_conf))
            .wrap(SecurityHeaders)
            .wrap(session_middleware)
            .configure(configure_app)
    })
    .bind_rustls_0_23((config.host.as_str(), config.port), tls_config)?
    .run()
    .await?;
    Ok(())
}

// --- Helper Functions ---

/// Loads TLS certificate and key from file for rustls v0.23.
/// This function now returns a `Result` to avoid panicking on I/O or parsing errors.
fn load_rustls_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let config_builder = ServerConfig::builder().with_no_client_auth();

    let cert_file = &mut BufReader::new(File::open("certs/cert.pem")?);
    let key_file = &mut BufReader::new(File::open("certs/key.pem")?);

    let cert_chain = certs(cert_file)?
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();

    let mut keys = pkcs8_private_keys(key_file)?;
    if keys.is_empty() {
        return Err("Could not locate PKCS8 private keys in key.pem.".into());
    }

    let private_key = PrivateKeyDer::Pkcs8(keys.remove(0).into());

    Ok(config_builder.with_single_cert(cert_chain, private_key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        dev::Service,
        http::{header, StatusCode},
        test,
    };
    use scraper::{Html, Selector};
    use serde_json::Value;
    use std::str;

    /// Helper to build the application for testing.
    /// It mirrors the main application setup but disables `cookie_secure` for non-TLS test environments.
    async fn setup_test_app() -> impl Service<actix_web::dev::ServiceRequest, Response = actix_web::dev::ServiceResponse, Error = actix_web::Error>
    {
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
                // In tests, we don't use TLS, so `cookie_secure` must be false.
                .cookie_secure(false)
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Strict)
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(Duration::seconds(config.session_max_age_seconds as i64)),
                )
                .build();

        test::init_service(
            App::new()
                .app_data(web::Data::new(config.clone()))
                .app_data(web::Data::new(tera.clone()))
                .wrap(Governor::new(&governor_conf))
                .wrap(SecurityHeaders)
                .wrap(session_middleware)
                .configure(configure_app),
        )
        .await
    }

    /// Helper to extract CSRF token from an HTML body using a proper parser.
    /// This is more robust than string splitting and resilient to template changes.
    fn extract_csrf_token(body: &str) -> String {
        let document = Html::parse_document(body);
        let selector = Selector::parse("input[name=\"csrf_token\"]").unwrap();
        document
            .select(&selector)
            .next()
            .and_then(|input| input.value().attr("value"))
            .unwrap_or("")
            .to_string()
    }

    #[actix_web::test]
    async fn test_unauthenticated_access_is_denied() {
        // Arrange
        let app = setup_test_app().await;
        let req = test::TestRequest::get().uri("/").to_request();

        // Act
        let resp = test::call_service(&app, req).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_login_page_loads_with_headers_and_csrf() {
        // Arrange
        let app = setup_test_app().await;
        let req = test::TestRequest::get().uri("/login").to_request();

        // Act
        let resp = test::call_service(&app, req).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        // Assert that critical security headers are present
        assert!(resp.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");

        // Assert that a CSRF token is embedded in the form
        let body = test::read_body(resp).await;
        let body_str = str::from_utf8(&body).unwrap();
        let token = extract_csrf_token(body_str);
        assert!(!token.is_empty(), "CSRF token should be present in the login form");
    }

    #[actix_web::test]
    async fn test_full_authentication_flow() {
        // Arrange
        let app = setup_test_app().await;

        // --- Step 1: Visit login page to get session and CSRF cookies/token ---
        let req = test::TestRequest::get().uri("/login").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Extract cookies and the HTML CSRF token for the next request
        let session_cookie = resp.response().cookies().find(|c| c.name() == "erp-session").expect("Session cookie not found").clone();
        let csrf_cookie = resp.response().cookies().find(|c| c.name() == "csrf-token").expect("CSRF cookie not found").clone();
        let body = test::read_body(resp).await;
        let csrf_token_from_html = extract_csrf_token(str::from_utf8(&body).unwrap());

        // --- Step 2: Submit login form with valid credentials and CSRF token ---
        let login_form = format!("username=admin&password=password123&csrf_token={}", csrf_token_from_html);
        let req = test::TestRequest::post()
            .uri("/login")
            .cookie(session_cookie.clone())
            .cookie(csrf_cookie)
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(login_form).to_request();
        let resp = test::call_service(&app, req).await;

        // Assert successful login (redirect to dashboard)
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "Successful login should redirect");
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/");
        let auth_cookie = resp.response().cookies().find(|c| c.name() == "erp-session").expect("Auth cookie not found").clone();

        // --- Step 3: Access a protected route with the new authenticated session cookie ---
        let req = test::TestRequest::get().uri("/").cookie(auth_cookie.clone()).to_request();
        let resp = test::call_service(&app, req).await;

        // Assert access is granted and page content is correct
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        assert!(str::from_utf8(&body).unwrap().contains("Welcome, admin"), "Dashboard should welcome the logged-in user");

        // --- Step 4: Logout from the authenticated session ---
        let req = test::TestRequest::post().uri("/logout").cookie(auth_cookie).to_request();
        let resp = test::call_service(&app, req).await;

        // Assert successful logout (redirect to login)
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");

        // Assert that the session cookie was cleared
        let logout_cookie = resp.response().cookies().find(|c| c.name() == "erp-session").unwrap();
        assert_eq!(logout_cookie.max_age().unwrap().as_secs(), 0, "Session cookie should be cleared on logout");
    }

    #[actix_web::test]
    async fn test_login_with_invalid_csrf_is_forbidden() {
        // Arrange
        let app = setup_test_app().await;
        let login_form = "username=admin&password=password123&csrf_token=invalidtoken";
        let req = test::TestRequest::post()
            .uri("/login")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(login_form).to_request();

        // Act
        let resp = test::call_service(&app, req).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn test_login_with_invalid_credentials_fails() {
        // Arrange: Get valid session and CSRF cookies/token
        let app = setup_test_app().await;
        let req = test::TestRequest::get().uri("/login").to_request();
        let resp = test::call_service(&app, req).await;
        let session_cookie = resp.response().cookies().find(|c| c.name() == "erp-session").unwrap().clone();
        let csrf_cookie = resp.response().cookies().find(|c| c.name() == "csrf-token").unwrap().clone();
        let body = test::read_body(resp).await;
        let csrf_token_from_html = extract_csrf_token(str::from_utf8(&body).unwrap());

        // Act: Attempt to login with a bad password
        let login_form = format!("username=admin&password=wrongpassword&csrf_token={}", csrf_token_from_html);
        let req = test::TestRequest::post()
            .uri("/login")
            .cookie(session_cookie)
            .cookie(csrf_cookie)
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(login_form).to_request();
        let resp = test::call_service(&app, req).await;

        // Assert: The request is rejected with a specific error message
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = test::read_body(resp).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["message"], "credentials: Invalid username or password.");
    }
}
