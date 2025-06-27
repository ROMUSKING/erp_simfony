use crate::errors::AppError;
use actix_session::Session;
use actix_web::{
    dev::Payload, guard, web, FromRequest, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use std::future::{ready, Ready};

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
impl FromRequest for AuthSession {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // This relies on the SessionMiddleware being registered.
        ready(Ok(AuthSession(Session::from_request(req, payload).into_inner().unwrap())))
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
#[derive(Deserialize)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

/// Handler for the POST /login request.
pub async fn login_post(
    session: AuthSession,
    form: web::Form<LoginData>,
) -> Result<impl Responder, AppError> {
    // In a real application, you would validate the password against a hash here.
    let user = User { username: form.username.clone() };
    session.login(user)?;
    Ok(HttpResponse::SeeOther().append_header(("Location", "/")).finish())
}