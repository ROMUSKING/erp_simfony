README: Production-Hardened Composable Enterprise
This project is a security-hardened starter template for building web applications based on the principles of "The Composable Enterprise" blueprint. It uses a Rust backend with the Actix Web framework and HTMX for dynamic frontends.
This version incorporates fixes from multiple, in-depth security audits, addressing critical vulnerabilities and implementing best practices for production-level security.
Key Security Enhancements
Strict, Nonce-Based Content-Security-Policy (CSP): The application implements a strict CSP that disallows all inline scripts. It generates a unique cryptographic nonce for each request, ensuring that only server-authorized scripts can execute, providing a robust defense against Cross-Site Scripting (XSS).
Configurable Settings via Environment Variables: Key operational parameters like rate limiting and the application port are now configurable via a .env file, making the application adaptable to different environments without code changes.
Fixed Session Timeouts: Session cookies are configured with a specific maximum age (e.g., 1 hour), ensuring users are logged out after a period of inactivity, which is a critical security measure against session hijacking.
Sanitized Logging: Logging practices have been refined to prevent sensitive user data from being written to system logs, mitigating the risk of information disclosure.
Correct CSRF Protection: A critical flaw in the CSRF token generation logic has been fixed. Tokens are now correctly generated and validated for each session.
Secure Error Handling: The application no longer leaks internal details in error messages.
Persistent Session Keys: The server generates and persists a secret key for signing session cookies.
Input Validation Framework: Uses the validator crate to enforce strict validation rules on all user-submitted data.
HTTPS By Default: The server runs exclusively over TLS (HTTPS). It does not listen on HTTP, so a redirect is not necessary.
Project Structure
.
├── .env.example    <- Example environment variables
├── Cargo.toml
├── certs/          <- Generate certs here
├── session_key.bin <- Auto-generated session key
├── src
│   ├── config.rs
│   ├── errors.rs
│   └── main.rs
├── static
│   ├── main.js
│   └── style.css
└── templates
    └── index.html.tera


.env.example: An example file for environment variables. Copy this to .env for local configuration.
src/config.rs: A new module for loading and managing configuration from environment variables.
static/main.js: Contains all client-side JavaScript, enabling a strict CSP.
Getting Started
1. Prerequisites
Rust
OpenSSL (or similar tool) to generate TLS certificates.
2. Generate Self-Signed Certificates
For local development, create a self-signed TLS certificate.
# Create a directory for the certificates
mkdir certs

# Generate the private key and certificate
openssl req -x509 -newkey rsa:4096 -nodes -keyout certs/key.pem -out certs/cert.pem -days 365 -subj "/CN=localhost"


3. Configure Environment
Copy the example .env file. Important: Add session_key.bin to your .gitignore file to prevent the secret key from being committed to version control.
cp .env.example .env
echo "session_key.bin" >> .gitignore


4. Run the Application
Navigate to the project directory.
Run the application:
cargo run
The server will start, and a session_key.bin file will be created.
Open your web browser and go to https://127.0.0.1:8443 (or the port specified in your .env file).
Note: Your browser will show a security warning because the certificate is self-signed. You must accept this for local development. In production, you must use a certificate from a trusted Certificate Authority (CA) like Let's Encrypt.
