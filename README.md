# Composable Enterprise ERP Simulation

A hardened, composable enterprise web application built with Rust and the Actix Web framework. This project serves as a simulation of a secure internal tool, demonstrating features like user authentication, CSRF protection, and secure HTTP headers.

## ✨ Features

- **Secure Authentication**: Complete login/logout flow with server-side sessions.
- **Password Hashing**: Uses `bcrypt` for secure password storage.
- **Route Protection**: Critical routes are only accessible to authenticated users.
- **Security Hardening**:
  - Cross-Site Request Forgery (CSRF) protection on all state-changing requests.
  - Content Security Policy (CSP) with nonce to prevent XSS attacks.
  - Secure headers like `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security`.
- **HTTPS by Default**: Uses self-signed certificates for local development.
- **Configuration Management**: Settings are managed via a `.env` file.
- **Templating**: Uses the Tera template engine for server-side rendering.

## 🚀 Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- **Rust Toolchain**: Ensure you have Rust installed. If not, get it from rustup.rs.
- **OpenSSL**: Required for generating self-signed SSL certificates.

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/ROMUSKING/erp_simfony.git
    cd erp_simfony
    ```

2.  **Create the configuration file:**
    Copy the example environment file to create your own local configuration.
    ```sh
    cp .env.example .env
    ```
    The default values in this file are suitable for local development.

3.  **Generate Self-Signed Certificates:**
    The application is configured to run over HTTPS. You need to generate a local certificate and private key.

    ```sh
    # Create the directory for certificates
    mkdir certs

    # Generate the key and certificate
    openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -sha256 -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
    ```
    > **Note**: The `.gitignore` file is configured to prevent `key.pem` from being committed to the repository.

4.  **Build and run the application:**
    ```sh
    cargo run --release --bin simfony
    ```

##  usage Usage

Once the application is running, you can access it in your browser:

- **URL**: https://localhost:8443
  - You will likely see a browser warning because the certificate is self-signed. You can safely proceed.

- **Default Credentials**:
  - **Username**: `admin`
  - **Password**: `password123`

## 📂 Project Structure

```
erp_simfony/
├── certs/              # Stores SSL certificates (ignored by Git)
├── src/                # Source code
│   ├── auth.rs         # User authentication logic
│   ├── config.rs       # Configuration loading
│   ├── errors.rs       # Custom error handling
│   └── main.rs         # Application entrypoint, routes, and handlers
├── static/             # Static assets (CSS, JS, images)
├── templates/          # Tera HTML templates
├── .env.example        # Example environment configuration
├── .gitignore          # Specifies files for Git to ignore
├── Cargo.toml          # Project dependencies and metadata
└── README.md           # This file
```