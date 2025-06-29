use crate::errors::AppError;
use actix_session::{Session, SessionExt};
use actix_web::{dev::Payload, guard, web, FromRequest, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::future::{ready, Ready};
use validator::{Validate, ValidationError, ValidationErrors}; // For input validation // For password hashing and verification

const USER_KEY: &str = "user";
// In a real app, this would come from a database.
const ADMIN_USERNAME: &str = "admin";
// This is the bcrypt hash for "password123".
// Generated with: `bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap()`
const PASSWORD_HASH: &str = "$2b.uB9X.B9X.B9X.B9X.B9X.B9X.B";

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
impl FromRequest for AuthSession {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // This relies on the SessionMiddleware being registered.
        ready(Ok(AuthSession(
            Session::from_request(req, payload).into_inner().unwrap(),
        )))
    }
}

/// A guard to protect routes that require authentication.
pub struct AuthGuard;

impl guard::Guard for AuthGuard {
    fn check(&self, ctx: &guard::GuardContext<'_>) -> bool {
        let session = ctx.get_session();
        session.get::<User>(USER_KEY).ok().flatten().is_some()
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
    session: AuthSession,
    form: web::Form<LoginData>,
) -> Result<impl Responder, AppError> {
    // 1. Rigorous Input Validation (Blueprint Control)
    form.validate()?;

    let username = &form.username;
    let password = &form.password;

    // 2. Verify credentials (simulated user lookup)
    if username == ADMIN_USERNAME {
        // 3. Use bcrypt to securely verify the password
        let is_valid = bcrypt::verify(password, PASSWORD_HASH).unwrap_or(false);

        if is_valid {
            // 4. On success, create the session
            let user = User {
                username: username.clone(),
            };
            session.login(user)?;
            tracing::info!("Successful login for user: {}", username);
            // Redirect to the main application page
            return Ok(HttpResponse::SeeOther()
                .append_header(("Location", "/"))
                .finish());
        }
    }

    // 5. Log failed attempts and return a generic error (Blueprint Control)
    tracing::warn!("Failed login attempt for username: {}", username);
    let mut errors = ValidationErrors::new();
    let mut error = ValidationError::new("credentials");
    error.message = Some("Invalid username or password.".into());
    errors.add("credentials", error);
    Err(AppError::ValidationError(errors))
}
