use dotenvy::dotenv;
use std::env;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub rate_limit_per_second: u64,
    pub rate_limit_burst_size: u32,
    pub hmac_secret: String,
    pub session_max_age_seconds: u64,
    pub admin_username: String,
    pub password_hash: String,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        println!("[DEBUG] Entered Config::from_env()");
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
        // AUDIT: Ensure HMAC_SECRET is provided, as it's critical for security.
        // This will error out if the variable is not set, preventing insecure startup.
        let hmac_secret = env::var("HMAC_SECRET")?;
        let session_max_age_seconds = env::var("SESSION_MAX_AGE_SECONDS")
            .unwrap_or_else(|_| "3600".to_string()) // Defaults to 1 hour
            .parse::<u64>()?;
        let admin_username = env::var("ADMIN_USERNAME")?;
        let password_hash = env::var("PASSWORD_HASH")?;

        println!("[DEBUG] Leaving Config::from_env()");

        Ok(Self {
            host,
            port,
            rate_limit_per_second,
            rate_limit_burst_size,
            hmac_secret,
            session_max_age_seconds,
            admin_username,
            password_hash,
        })
    }
}
