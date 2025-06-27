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