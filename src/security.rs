use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error, HttpMessage,
};
use base64::Engine;
use futures_util::future::{ready, LocalBoxFuture, Ready};

/// A struct to hold the CSP nonce, which is inserted into request extensions.
#[derive(Clone)]
pub struct Nonce(pub String);

/// Middleware transform for adding security headers.
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Ready<Result<SecurityHeadersMiddleware<S>, ()>> {
        ready(Ok(SecurityHeadersMiddleware { service }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Generate a new nonce for each request.
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);

        // Insert the nonce into request extensions so handlers can use it.
        req.extensions_mut().insert(Nonce(nonce.clone()));

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            // AUDIT FIX: Implement a strict, nonce-based CSP as per blueprint.
            let csp = format!("default-src 'self'; script-src 'self' 'nonce-{}'; object-src 'none'; base-uri 'self'; form-action 'self';", nonce);

            res.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                header::HeaderValue::from_str(&csp).unwrap(),
            );
            res.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );
            res.headers_mut().insert(
                header::X_FRAME_OPTIONS,
                header::HeaderValue::from_static("DENY"),
            );
            // Deprecated, but good for older browsers. CSP is the primary defense.
            res.headers_mut().insert(
                header::X_XSS_PROTECTION,
                header::HeaderValue::from_static("1; mode=block"),
            );
            // AUDIT FIX: Add Strict-Transport-Security header as per blueprint.
            // This tells browsers to only use HTTPS for this site for the next year.
            res.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );

            Ok(res)
        })
    }
}
