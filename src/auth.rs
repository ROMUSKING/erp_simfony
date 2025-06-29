use crate::config::Config;
use crate::errors::AppError;
use actix_session::Session;
use actix_session::SessionExt;
use actix_web::{dev::Payload, web, FromRequest, HttpRequest, HttpResponse, Responder};
use futures_util::future::{ready, Ready};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors}; // For input validation

const USER_KEY: &str = "user";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub username: String,
}

/// A wrapper around actix_session::Session to provide typed access to session data.
pub struct AuthSession(Session);

impl AuthSession {
    /// Retrieves the username from the session, if the user is logged in.
    pub fn get_username(&self) -> Option<String> {
        self.0
            .get::<User>(USER_KEY)
            .ok()
            .flatten()
            .map(|u| u.username)
    }

    /// Inserts user information into the session, effectively logging them in.
    pub fn login(&self, user: User) -> Result<(), AppError> {
        self.0.insert(USER_KEY, user)?;
        Ok(())
    }

    /// Removes user information from the session, logging them out.
    pub fn logout(&self) {
        self.0.remove(USER_KEY);
    }
}

/// Implements the FromRequest trait so that AuthSession can be used as a handler extractor.
/// Redirects to /login if not authenticated.
impl FromRequest for AuthSession {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let session = req.get_session();
        let is_authenticated = session.get::<User>(USER_KEY).ok().flatten().is_some();
        if is_authenticated {
            ready(Ok(AuthSession(session)))
        } else {
            let resp = HttpResponse::SeeOther()
                .append_header(("Location", "/login"))
                .finish();
            ready(Err(actix_web::error::InternalError::from_response(
                "Not authenticated",
                resp,
            )
            .into()))
        }
    }
}

/// Represents the data submitted from the login form.
/// AUDIT FIX: Added server-side validation as per blueprint.
#[derive(Deserialize, Validate)]
pub struct LoginData {
    #[validate(length(min = 1, message = "Username cannot be empty"))]
    pub username: String,
    #[validate(length(min = 1, message = "Password cannot be empty"))]
    pub password: String,
}

/// Handler for the POST /login request.
/// AUDIT FIX: Replaced placeholder logic with secure password verification.
pub async fn login_post(
    session: Session,
    form: web::Form<LoginData>,
    config: web::Data<Config>, // <-- Add config extractor
) -> Result<impl Responder, AppError> {
    form.validate()?;

    let username = &form.username;
    let password = &form.password;

    // Use config values instead of constants
    if username == &config.admin_username {
        let is_valid = bcrypt::verify(password, &config.password_hash).unwrap_or(false);

        if is_valid {
            let user = User {
                username: username.clone(),
            };
            AuthSession(session).login(user)?;
            tracing::info!("Successful login for user: {}", username);
            return Ok(HttpResponse::SeeOther()
                .append_header(("Location", "/app"))
                .finish());
        }
    }

    tracing::warn!("Failed login attempt for username: {}", username);
    let mut errors = ValidationErrors::new();
    let mut error = ValidationError::new("credentials");
    error.message = Some("Invalid username or password.".into());
    errors.add("credentials", error);
    Err(AppError::ValidationError(errors))
}
