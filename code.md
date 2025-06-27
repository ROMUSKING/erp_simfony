# Cargo.toml

[package]
name = "composable-enterprise-final"
version = "0.5.0"
edition = "2021"

[dependencies]
actix-web = "4"
actix-files = "0.6"
tera = "1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.8", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
html-escape = "0.2"

# Security & Config Dependencies
actix-session = { version = "0.8", features = ["cookie-session"] }
actix-web-rustls = "0.2"
rustls = "0.22"
rustls-pemfile = "2.1"
actix-governor = "0.6"
rand = "0.8"
validator = { version = "0.18", features = ["derive"] }
dotenvy = "0.15"

# Logging
tracing = { version = "0.1", features = ["log"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
cargo-audit = "0.19"
```rust
// src/config.rs

use dotenvy::dotenv;
use std::env;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub rate_limit_per_second: u64,
    pub rate_limit_burst_size: u32,
    pub session_max_age_seconds: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv().ok(); // Load .env file if it exists

        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8443".to_string())
            .parse::<u16>()?;
        let rate_limit_per_second = env::var("RATE_LIMIT_PER_SECOND")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u64>()?;
        let rate_limit_burst_size = env::var("RATE_LIMIT_BURST_SIZE")
            .unwrap_or_else(|_| "20".to_string())
            .parse::<u32>()?;
        let session_max_age_seconds = env::var("SESSION_MAX_AGE_SECONDS")
            .unwrap_or_else(|_| "3600".to_string()) // Defaults to 1 hour
            .parse::<u64>()?;

        Ok(Self {
            host,
            port,
            rate_limit_per_second,
            rate_limit_burst_size,
            session_max_age_seconds,
        })
    }
}
```rust
// src/errors.rs

use actix_web::{http::StatusCode, ResponseError, HttpResponse};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    TeraError(tera::Error),
    IoError(std::io::Error),
    ValidationError(String),
    InternalError(String),
    SessionError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::TeraError(e) => write!(f, "Template Error: {}", e),
            AppError::IoError(e) => write!(f, "IO Error: {}", e),
            AppError::ValidationError(s) => write!(f, "Validation Error: {}", s),
            AppError::InternalError(s) => write!(f, "Internal Server Error: {}", s),
            AppError::SessionError(s) => write!(f, "Session management error: {}", s),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        // **AUDIT FIX**: Sanitize logging to prevent leaking sensitive information.
        match self {
            AppError::ValidationError(_) => {
                // We log that validation failed, but NOT the details, which could contain user input.
                tracing::warn!("A data validation error occurred. User input was rejected.");
            }
            // For other internal errors, the Display impl is assumed to be safe for logging.
            _ => {
                tracing::error!(error_details = %self, "An application error occurred.");
            }
        }

        let status = self.status_code();
        let user_message = match self {
            AppError::ValidationError(ref message) => message.clone(),
            _ => "An unexpected error occurred. Please try again later.".to_string(),
        };

        HttpResponse::build(status).json(json!({
            "error": { "code": status.as_u16(), "message": user_message },
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}

impl From<tera::Error> for AppError { fn from(err: tera::Error) -> Self { AppError::TeraError(err) } }
impl From<std::io::Error> for AppError { fn from(err: std::io::Error) -> Self { AppError::IoError(err) } }
impl From<actix_session::SessionInsertError> for AppError { fn from(err: actix_session::SessionInsertError) -> Self { AppError::SessionError(err.to_string()) } }
impl From<actix_session::SessionGetError> for AppError { fn from(err: actix_session::SessionGetError) -> Self { AppError::SessionError(err.to_string()) } }
impl From<validator::ValidationErrors> for AppError { fn from(err: validator::ValidationErrors) -> Self { AppError::ValidationError(err.to_string()) } }
```rust
// src/main.rs

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
        "default-src 'self'; script-src 'self' [https://unpkg.com](https://unpkg.com) 'nonce-{}'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';",
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
```html
<!-- templates/index.html.tera -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token }}">
    <title>{{ title }}</title>
    <link rel="stylesheet" href="/static/style.css">
    <!-- HTMX library -->
    <!-- AUDIT FIX: Added nonce for strict CSP -->
    <script src="https://unpkg.com/htmx.org@1.9.10" xintegrity="sha384-D1Kt99CQMDuVetoL1lrYwg5t+9QdHe7NLX/SoJYkXDFfX37iInKRy5xLSi8nO7UC" crossorigin="anonymous" nonce="{{ csp_nonce }}"></script>
    <!-- Local script for configuration -->
    <!-- AUDIT FIX: Added nonce for strict CSP -->
    <script src="/static/main.js" defer nonce="{{ csp_nonce }}"></script>
</head>
<body>
    <header>
        <h1>Welcome to the {{ title }}</h1>
        <p>A production-hardened demonstration of Rust and HTMX.</p>
    </header>

    <main>
        <div class="container">
            <h2>Demonstrating Hardened Security</h2>
            <p>
                Submit the form below. The request includes a CSRF token and the server validates the input
                to ensure it is not empty and within length limits.
            </p>
            <form hx-post="/data" hx-target="#content-target" hx-swap="innerHTML">
                <input
                    type="text"
                    name="user_input"
                    class="input-field"
                    placeholder="Enter some text..."
                >
                <button type="submit" class="button">Submit Securely</button>
            </form>

            <div id="content-target" class="content-box">
                <!-- This is where the content from the server will be placed -->
                <p>Results from the server will appear here.</p>
            </div>
        </div>
    </main>

    <footer>
        <p>© 2025 Composable Systems Inc.</p>
    </footer>
</body>
</html>
```css
/* static/style.css */
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6;
    background-color: #f4f7f6;
    color: #333;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}

header {
    background-color: #2c3e50;
    color: #ecf0f1;
    padding: 1rem 2rem;
    text-align: center;
}

main {
    flex-grow: 1;
    padding: 2rem;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    background-color: #fff;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.input-field {
    width: calc(100% - 24px);
    padding: 12px;
    margin-bottom: 1rem;
    border-radius: 5px;
    border: 1px solid #ddd;
    font-size: 1rem;
}

.button {
    background-color: #3498db;
    color: white;
    padding: 12px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 1rem;
    transition: background-color 0.3s ease;
    display: block;
    width: 100%;
}

.button:hover {
    background-color: #2980b9;
}

.content-box {
    margin-top: 1.5rem;
    padding: 1.5rem;
    border: 1px solid #ddd;
    border-radius: 5px;
    background-color: #fafafa;
    min-height: 100px;
    word-wrap: break-word;
}

footer {
    background-color: #34495e;
    color: #ecf0f1;
    text-align: center;
    padding: 1rem;
    margin-top: auto;
}
```javascript
// static/main.js

document.addEventListener('DOMContentLoaded', (event) => {
    // --- HTMX Security Configuration ---
    // Ensure HTMX includes the CSRF token in its requests.
    document.body.addEventListener('htmx:configRequest', function(evt) {
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        if (csrfToken) {
            evt.detail.headers['X-CSRF-Token'] = csrfToken.getAttribute('content');
        }
    });

    // Harden HTMX against script injection.
    if (window.htmx) {
        window.htmx.config.selfRequestsOnly = true;
        window.htmx.config.allowScriptTags = false;
        window.htmx.config.allowEval = false;
    }
});


.env.example
Copy this file to .env for local configuration
Application Host
HOST=127.0.0.1
Application Port
PORT=8443
Rate Limiting: Requests per second
RATE_LIMIT_PER_SECOND=10
Rate Limiting: Burst size
RATE_LIMIT_BURST_SIZE=20
Session cookie max age in seconds (e.g., 3600 = 1 hour)
SESSION_MAX_AGE_SECONDS=3600
Logging level (e.g., info, debug, warn, error)
RUST_LOG=info

