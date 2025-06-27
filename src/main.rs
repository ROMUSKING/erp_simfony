use actix_governor::{Governor, GovernorConfigBuilder};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, middleware};
use actix_web::cookie::{Key, SameSite, time::Duration};
use rand::{Rng, distributions::Alphanumeric};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{BufReader, Write};
use std::sync::Mutex;
use tera::{Context, Tera};
use uuid::Uuid;
use validator::Validate;
use serde::Deserialize;

mod errors;
mod config;
use crate::errors::AppError;
use crate::config::Config;

struct AppState {
    tera: Mutex<Tera>,
}

#[derive(Deserialize, Validate)]
struct FormData {
    #[validate(length(min = 1, message = "Input cannot be empty."))]
    #[validate(length(max = 100, message = "Input must be less than 100 characters."))]
    user_input: String,
}

fn get_or_create_csrf_token(session: &Session) -> Result<String, AppError> {
    match session.get::<String>("csrf_token")? {
        Some(token) => Ok(token),
        None => {
            let new_token = Uuid::new_v4().to_string();
            session.insert("csrf_token", new_token.clone())?;
            Ok(new_token)
        }
    }
}

#[get("/")]
async fn index(data: web::Data<AppState>, session: Session) -> Result<impl Responder, AppError> {
    let tera = data.tera.lock().expect("Failed to lock Tera mutex");
    let mut ctx = Context::new();

    // **AUDIT FIX**: Generate a nonce for the Content-Security-Policy.
    let csp_nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();

    let csrf_token = get_or_create_csrf_token(&session)?;
    ctx.insert("title", "Final Hardened Composable Enterprise");
    ctx.insert("csrf_token", &csrf_token);
    ctx.insert("csp_nonce", &csp_nonce);

    let rendered = tera.render("index.html.tera", &ctx)?;

    // **AUDIT FIX**: Build the dynamic CSP header here instead of using middleware.
    let csp_header_value = format!(
        "default-src 'self'; script-src 'self' https://unpkg.com 'nonce-{}'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';",
        csp_nonce
    );

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", csp_header_value))
        .content_type("text/html; charset=utf-8")
        .body(rendered))
}

#[post("/data")]
async fn post_data(session: Session, form: web::Form<FormData>, req: web::HttpRequest) -> Result<impl Responder, AppError> {
    form.validate()?;
    let req_csrf_token = req.headers().get("X-CSRF-Token").and_then(|v| v.to_str().ok()).unwrap_or("");
    let session_csrf_token = get_or_create_csrf_token(&session)?;
    if req_csrf_token != session_csrf_token {
        tracing::warn!("CSRF token mismatch detected for a request.");
        return Err(AppError::ValidationError("Invalid security token.".to_string()));
    }
    let sanitized_input = html_escape::encode_text(&form.user_input);
    let html_fragment = format!("<h4>Validation Successful!</h4><p>Server received: <strong>{}</strong></p>", sanitized_input);
    Ok(HttpResponse::Ok().content_type("text/html").body(html_fragment))
}

fn load_rustls_config() -> Result<ServerConfig, AppError> {
    let config = ServerConfig::builder().with_safe_defaults().with_no_client_auth();
    let cert_file = &mut BufReader::new(File::open("certs/cert.pem")?);
    let key_file = &mut BufReader::new(File::open("certs/key.pem")?);
    let cert_chain = certs(cert_file)?.into_iter().map(Certificate).collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)?.into_iter().map(PrivateKey).collect();
    if keys.is_empty() { return Err(AppError::InternalError("Could not find private key".to_string())); }
    config.with_single_cert(cert_chain, keys.remove(0)).map_err(|e| AppError::InternalError(format!("TLS config error: {}", e)))
}

fn load_or_generate_session_key() -> Result<Key, std::io::Error> {
    let key_path = "session_key.bin";
    if let Ok(key_data) = std::fs::read(key_path) {
        if key_data.len() == 64 { return Ok(Key::from(&key_data)); }
    }
    let key = Key::generate();
    let mut file = File::create(key_path)?;
    file.write_all(key.master())?;
    tracing::info!("Generated and saved new session key to {}", key_path);
    Ok(key)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let config = Config::from_env().expect("Failed to load configuration from environment.");
    let tera = Tera::new("templates/**/*").expect("Failed to initialize Tera.");
    let app_state = web::Data::new(AppState { tera: Mutex::new(tera) });
    let secret_key = load_or_generate_session_key().expect("Failed to load or generate session key.");
    let governor_conf = GovernorConfigBuilder::default().per_second(config.rate_limit_per_second).burst_size(config.rate_limit_burst_size).finish().unwrap();
    let tls_config = load_rustls_config().expect("Failed to load TLS configuration.");

    tracing::info!("Starting server at https://{}:{}", config.host, config.port);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .wrap(Governor::new(&governor_conf))
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("final-enterprise-session".to_string())
                    .cookie_secure(true)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Strict)
                    // **AUDIT FIX**: Set a fixed session timeout.
                    .cookie_max_age(Duration::seconds(config.session_max_age_seconds))
                    .build(),
            )
            // **AUDIT FIX**: CSP is now set dynamically in the request handler.
            // Other default headers are still set here.
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-XSS-Protection", "1; mode=block"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .add(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
                    .add(("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"))
            )
            .service(index)
            .service(post_data)
            .service(actix_files::Files::new("/static", "static"))
    })
    .bind_rustls_0_22((config.host.clone(), config.port), tls_config)?
    .run()
    .await
}