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
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{Key, SameSite},
    web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
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
    context.insert("nonce", &nonce);
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
            .service(
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
                                web::resource("")
                                    .route(web::get().to(login_get))
                                    .route(web::post().to(login_post)),
                            ),
                    ),
            )
            // Serve static files from the "static" directory, as described in README.md
            .service(Files::new("/static", "./static"))
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
