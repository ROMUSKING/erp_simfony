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