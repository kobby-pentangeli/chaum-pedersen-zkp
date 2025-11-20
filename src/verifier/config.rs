use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tonic::Status;

/// Server configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Hostname or IP address to bind to.
    pub host: String,
    /// Port number to listen on.
    pub port: u16,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitSettings,
    /// Metrics exporter configuration.
    pub metrics: MetricsSettings,
    /// TLS configuration.
    pub tls: TlsSettings,
}

impl ServerConfig {
    /// Converts host and port into a socket address.
    ///
    /// # Panics
    /// Panics if the host and port cannot be parsed into a valid socket address.
    /// This should only happen if the configuration is malformed.
    pub fn addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|e| {
                panic!(
                    "Invalid server address configuration (host: {}, port: {}): {}",
                    self.host, self.port, e
                )
            })
    }
}

/// Rate limiting settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitSettings {
    /// Maximum requests per minute per client.
    pub requests_per_minute: u64,
    /// Burst capacity for short-term spikes.
    pub burst: u64,
}

impl RateLimitSettings {
    /// Creates a rate limiter from these settings.
    pub fn build_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.requests_per_minute, self.burst)
    }
}

/// Rate limiter using token bucket algorithm.
///
/// Implements a token bucket with configurable rate and burst capacity.
/// Thread-safe and suitable for concurrent access.
#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<Mutex<RateLimiterState>>,
    rate: u64,
    burst: u64,
}

struct RateLimiterState {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    /// Creates a new rate limiter from configuration settings.
    ///
    /// # Arguments
    /// * `settings` - Rate limit configuration settings
    pub fn from_config(settings: &RateLimitSettings) -> Self {
        settings.build_limiter()
    }

    /// Creates a new rate limiter.
    ///
    /// # Arguments
    /// * `requests_per_minute` - Maximum sustained request rate
    /// * `burst` - Maximum burst capacity (additional requests allowed in short bursts)
    pub fn new(requests_per_minute: u64, burst: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimiterState {
                tokens: burst as f64,
                last_update: Instant::now(),
            })),
            rate: requests_per_minute,
            burst,
        }
    }

    /// Attempts to acquire a token for a request.
    ///
    /// Returns `Ok(())` if a token was acquired, `Err(Status)` if rate limit exceeded.
    pub async fn check_rate_limit(&self) -> Result<(), Status> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update).as_secs_f64();

        let tokens_per_second = self.rate as f64 / 60.0;
        state.tokens = (state.tokens + elapsed * tokens_per_second).min(self.burst as f64);

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            state.last_update = now;
            Ok(())
        } else {
            Err(Status::resource_exhausted("Rate limit exceeded"))
        }
    }
}

/// Metrics exporter settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSettings {
    /// Whether metrics export is enabled.
    pub enabled: bool,
    /// Hostname or IP address for metrics server.
    pub host: String,
    /// Port number for metrics server.
    pub port: u16,
}

impl MetricsSettings {
    /// Converts host and port into a socket address for metrics server.
    ///
    /// # Panics
    /// Panics if the host and port cannot be parsed into a valid socket address.
    /// This should only happen if the configuration is malformed.
    pub fn addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|e| {
                panic!(
                    "Invalid metrics address configuration (host: {}, port: {}): {}",
                    self.host, self.port, e
                )
            })
    }
}

/// TLS configuration settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// Path to TLS certificate file (PEM format).
    pub cert_path: String,
    /// Path to TLS private key file (PEM format).
    pub key_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 50051,
            rate_limit: RateLimitSettings {
                requests_per_minute: 100,
                burst: 10,
            },
            metrics: MetricsSettings {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 9090,
            },
            tls: TlsSettings {
                enabled: false,
                cert_path: String::new(),
                key_path: String::new(),
            },
        }
    }
}

impl ServerConfig {
    /// Loads configuration from `.env` file, TOML file, and environment variables.
    ///
    /// Configuration priority (highest to lowest):
    /// 1. Environment variables with `SERVER_` prefix (e.g., `SERVER_PORT=8080`)
    /// 2. TOML configuration file (if exists)
    /// 3. `.env` file (if exists)
    /// 4. Built-in defaults
    ///
    /// The `.env` file is automatically loaded from the current directory or any parent
    /// directory (searches up the directory tree). If no `.env` file is found, this is
    /// not considered an error and configuration continues with other sources.
    ///
    /// The TOML file path can be set via `SERVER_CONFIG_PATH` environment variable.
    /// If not set, defaults to `./config/server.toml`. If the file doesn't exist,
    /// it is silently skipped (not an error).
    ///
    /// # Environment Variable Examples
    /// ```bash
    /// # In `.env` file or shell:
    /// SERVER_HOST=0.0.0.0
    /// SERVER_PORT=8080
    /// SERVER_RATE_LIMIT_REQUESTS_PER_MINUTE=200
    /// SERVER_RATE_LIMIT_BURST=20
    /// SERVER_METRICS_ENABLED=true
    /// SERVER_METRICS_PORT=9090
    /// SERVER_TLS_ENABLED=true
    /// SERVER_TLS_CERT_PATH=/etc/certs/server.crt
    /// SERVER_TLS_KEY_PATH=/etc/certs/server.key
    /// ```
    ///
    /// # Errors
    /// Returns an error if the configuration is malformed or contains invalid values.
    #[allow(clippy::result_large_err)]
    pub fn from_env() -> figment::error::Result<Self> {
        use figment::Figment;
        use figment::providers::{Env, Format, Toml};

        // Attempt to load .env file (silently ignore if it doesn't exist)
        let _ = dotenvy::dotenv();

        let config_path = std::env::var("SERVER_CONFIG_PATH")
            .unwrap_or_else(|_| "config/server.toml".to_string());

        Figment::new()
            .merge(Toml::file(&config_path).nested())
            .merge(Env::prefixed("SERVER_").split("_"))
            .extract()
    }

    /// Validates the configuration for production readiness.
    ///
    /// # Errors
    /// Returns an error message if the configuration is invalid for production use.
    pub fn validate(&self) -> Result<(), String> {
        if self.tls.enabled {
            if self.tls.cert_path.is_empty() {
                return Err("TLS is enabled but cert_path is empty".to_string());
            }
            if self.tls.key_path.is_empty() {
                return Err("TLS is enabled but key_path is empty".to_string());
            }

            let cert_path = PathBuf::from(&self.tls.cert_path);
            if !cert_path.exists() {
                return Err(format!(
                    "TLS certificate file does not exist: {}",
                    self.tls.cert_path
                ));
            }

            let key_path = PathBuf::from(&self.tls.key_path);
            if !key_path.exists() {
                return Err(format!(
                    "TLS key file does not exist: {}",
                    self.tls.key_path
                ));
            }
        }

        if self.rate_limit.requests_per_minute == 0 {
            return Err("Rate limit requests_per_minute cannot be zero".to_string());
        }

        if self.rate_limit.burst == 0 {
            return Err("Rate limit burst cannot be zero".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(60, 10);

        for _ in 0..10 {
            assert!(limiter.check_rate_limit().await.is_ok());
        }
    }

    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(60, 5);

        for _ in 0..5 {
            limiter.check_rate_limit().await.unwrap();
        }

        assert!(limiter.check_rate_limit().await.is_err());
    }

    #[tokio::test]
    async fn rate_limiter_refills_tokens() {
        let limiter = RateLimiter::new(120, 2);

        limiter.check_rate_limit().await.unwrap();
        limiter.check_rate_limit().await.unwrap();
        assert!(limiter.check_rate_limit().await.is_err());

        tokio::time::sleep(Duration::from_millis(600)).await;

        assert!(limiter.check_rate_limit().await.is_ok());
    }

    #[test]
    fn rate_limit_settings_build_limiter() {
        let settings = RateLimitSettings {
            requests_per_minute: 100,
            burst: 10,
        };

        let limiter = settings.build_limiter();
        assert_eq!(limiter.rate, 100);
        assert_eq!(limiter.burst, 10);
    }
}
