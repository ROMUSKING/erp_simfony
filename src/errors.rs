use actix_session::{SessionGetError, SessionInsertError};
use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;
use validator::ValidationErrors;

#[derive(Debug)]
pub enum AppError {
    TeraError,
    IoError,
    ValidationError(ValidationErrors),
    #[allow(dead_code)]
    InternalError,
    SessionInsertError,
    SessionGetError,
    // Represents a logical error where a user is not authenticated.
    #[allow(dead_code)]
    Unauthorized,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // For logging, we must avoid printing the full inner error, which could
            // contain sensitive information (e.g., file paths from io::Error or the
            // contents of an inner error). We log the type of error, which is safe.
            AppError::TeraError => write!(f, "Template Error"),
            AppError::IoError => write!(f, "IO Error"),
            // The `field_errors` method is safe to log as it does not contain user input values.
            // It provides context on which validation rule failed, which is valuable for debugging.
            AppError::ValidationError(e) => write!(f, "Validation Error: {:?}", e.field_errors()),
            AppError::InternalError => write!(f, "Internal Server Error"),
            AppError::SessionInsertError => write!(f, "Session Insert Error"),
            AppError::SessionGetError => write!(f, "Session Get Error"),
            AppError::Unauthorized => write!(f, "Unauthorized Access"),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            // This is a client-side error (e.g., not logged in). This is not a server
            // failure, so we shouldn't return a 500. This replaces the check for the
            // now-removed `SessionGetError::NotPresent` variant.
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        // **AUDIT FIX**: Sanitize logging to prevent leaking sensitive information, as per the blueprint.
        // The `Display` implementation for `AppError` is designed to be safe for logging.
        match self {
            // Client-side errors (bad request, unauthorized) are logged as warnings.
            // The Display impl includes field details for validation, which is useful and safe.
            AppError::ValidationError(_) | AppError::Unauthorized => {
                tracing::warn!(error_details = %self, "A client-side error occurred.");
            }
            // All other errors are treated as internal server errors.
            _ => {
                // The Display impl is safe and provides the error type.
                tracing::error!(error_details = %self, "An internal server error occurred.");
            }
        }

        let status = self.status_code();
        let user_message = match self {
            AppError::ValidationError(ref errors) => {
                // Create a user-friendly, single-line error message from validation errors.
                errors
                    .field_errors()
                    .iter()
                    .map(|(field, errs)| {
                        let msg = errs.get(0)
                            .and_then(|e| e.message.as_ref())
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "is invalid".to_string());
                        format!("{}: {}", field, msg)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            }
            AppError::Unauthorized => "Authentication required. Please log in.".to_string(),
            _ => "An unexpected error occurred. Please try again later.".to_string(),
        };

        HttpResponse::build(status).json(json!({
            "error": { "code": status.as_u16(), "message": user_message },
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}

impl std::error::Error for AppError {}
impl From<tera::Error> for AppError {
    fn from(_err: tera::Error) -> Self {
        AppError::TeraError
    }
}
impl From<std::io::Error> for AppError {
    fn from(_err: std::io::Error) -> Self {
        AppError::IoError
    }
}
impl From<SessionInsertError> for AppError {
    fn from(_err: SessionInsertError) -> Self {
        AppError::SessionInsertError
    }
}
impl From<SessionGetError> for AppError {
    fn from(_err: SessionGetError) -> Self {
        AppError::SessionGetError
    }
}
impl From<ValidationErrors> for AppError {
    fn from(err: ValidationErrors) -> Self {
        AppError::ValidationError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body;
    use serde_json::Value;
    use validator::Validate;

    #[derive(Validate)]
    struct TestInput {
        #[validate(length(min = 1, message = "is required"))]
        field: String,
    }

    #[test]
    fn test_display_impl() {
        assert!(AppError::IoError.to_string().contains("IO Error"));
        assert!(AppError::InternalError.to_string().contains("Internal Server Error"));

        let invalid_input = TestInput { field: "".to_string() };
        let validation_errors = invalid_input.validate().unwrap_err();
        assert!(AppError::ValidationError(validation_errors).to_string().contains("Validation Error"));
    }

    #[actix_rt::test]
    async fn test_response_error_impl() {
        // Test Validation Error
        let invalid_input = TestInput { field: "".to_string() };
        let validation_errors = invalid_input.validate().unwrap_err();
        let app_error = AppError::from(validation_errors);
        assert_eq!(app_error.status_code(), StatusCode::BAD_REQUEST);
        let response = app_error.error_response();
        let body_bytes = body::to_bytes(response.into_body()).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["error"]["message"], "field: is required");

        // Test Unauthorized Error
        let unauthorized_error = AppError::Unauthorized;
        assert_eq!(unauthorized_error.status_code(), StatusCode::UNAUTHORIZED);
        let response = unauthorized_error.error_response();
        let body_bytes = body::to_bytes(response.into_body()).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["error"]["message"], "Authentication required. Please log in.");

        // Test Generic Internal Server Error
        let internal_error = AppError::InternalError;
        assert_eq!(internal_error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        let response = internal_error.error_response();
        let body_bytes = body::to_bytes(response.into_body()).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["error"]["message"], "An unexpected error occurred. Please try again later.");
    }

    #[test]
    fn test_from_impls() {
        // Test From<ValidationErrors>
        let invalid_input = TestInput { field: "".to_string() };
        let validation_errors = invalid_input.validate().unwrap_err();
        let app_error: AppError = validation_errors.into();
        assert!(matches!(app_error, AppError::ValidationError(_)));

        // The `From<SessionGetError>` implementation is trivial and difficult to test
        // without constructing a complex error object. The key logic for handling
        // unauthorized access is now tested directly via `AppError::Unauthorized`.
    }
}
