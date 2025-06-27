// Main application entrypoint.
// This file has been updated to be compatible with the latest dependencies
// specified in Cargo.toml, including rustls v0.23, actix-session v0.9,
// and actix-governor for rate limiting.

mod auth;
mod config;
mod errors;
mod security;

use actix_csrf::CsrfMiddleware;
use actix_files::Files;
use actix_governor::{Governor, GovernorConfigBuilder, Quota};
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{Key, SameSite},
    web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroU32;
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

async fn index(session: AuthSession) -> impl Responder {
    let username = session.get_username().unwrap_or_else(|| "Guest".to_string());
    HttpResponse::Ok().body(format!("Welcome, {}!", username))
}

async fn login_get(tera: web::Data<Tera>, req: HttpRequest) -> Result<impl Responder, AppError> {
    let mut context = tera::Context::new();
    context.insert("error", "");
    let nonce = req
        .extensions()
        .get::<Nonce>()
        .map_or_else(String::new, |n| n.0.clone());
    context.insert("nonce", &nonce);
    let rendered = tera.render("login.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

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

    // 2. Load configuration from .env file using `dotenvy`
    let config = Config::from_env()?;
    let app_config = web::Data::new(config.clone());

    // 3. Load TLS configuration with the updated rustls v0.23 API
    let tls_config = load_rustls_config()?;

    // 4. Configure rate limiting with `actix-governor`
    // AUDIT FIX: Use values from config instead of hardcoding, per blueprint.
    let rate_limit_per_second = NonZeroU32::new(config.rate_limit_per_second as u32)
        .ok_or("RATE_LIMIT_PER_SECOND must be non-zero")?;
    let governor_conf = GovernorConfigBuilder::default()
        .quota(Quota::per_second(rate_limit_per_second))
        .burst_size(config.rate_limit_burst_size)
        .finish()
        .unwrap();

    info!(
        "Starting server at https://{}:{}",
        config.host, config.port
    );

    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").unwrap();

        // 5. Configure session middleware for actix-session v0.9
        // This is created inside the closure because CookieSessionStore is not Clone.
        let session_key = Key::from(config.hmac_secret.as_bytes());
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                .cookie_name("erp-session".to_string())
                .cookie_secure(true)
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Strict)
                // Use `time::Duration` for session TTL, required by actix-session v0.9+
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(Duration::seconds(config.session_max_age_seconds as i64)),
                )
                .build();

        App::new()
            .app_data(app_config.clone())
            .app_data(web::Data::new(tera))
            // Middlewares are wrapped in reverse order of execution
            .wrap(TracingLogger::default()) // Structured request logging
            .wrap(Governor::new(&governor_conf)) // Rate limiting for all requests
            .wrap(SecurityHeaders) // Custom security headers (CSP, etc.)
            .wrap(session_middleware)
            .wrap(CsrfMiddleware::new()) // Must be after session to function correctly
            .service(
                web::scope("")
                    .service(web::resource("/").guard(AuthGuard).to(index))
                    .service(web::resource("/logout").post(logout))
                    .service(
                        web::resource("/login")
                            .route(web::get().to(login_get))
                            .route(web::post().to(login_post)),
                    ),
            )
            .service(Files::new("/static", "static"))
    })
    // 6. Use the new binding method for rustls v0.23 and config values
    .bind_rustls_023((config.host.as_str(), config.port), tls_config)?
    .run()
    .await?;
    Ok(())
}

// --- Helper Functions ---

/// Loads TLS certificate and key from file for rustls v0.23.
/// AUDIT FIX: Returns a Result to avoid panicking on I/O errors.
fn load_rustls_config() -> std::io::Result<ServerConfig> {
    let config_builder = ServerConfig::builder().with_no_client_auth();

    let cert_file = &mut BufReader::new(File::open("certs/cert.pem")?);
    let key_file = &mut BufReader::new(File::open("certs/key.pem")?);

    let cert_chain = certs(cert_file)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Could not parse certificate chain"))?;

    let mut keys = pkcs8_private_keys(key_file)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Could not parse private key"))?;

    if keys.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Could not locate PKCS 8 private keys in key.pem.",
        ));
    }

    config_builder
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(keys.remove(0)))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}