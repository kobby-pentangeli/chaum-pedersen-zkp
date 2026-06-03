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
    pub host: String,
    pub port: u16,
    pub rate_limit: RateLimitSettings,
    pub metrics: MetricsSettings,
    pub tls: TlsSettings,
}

impl ServerConfig {
    /// Resolves `host:port` to a socket address; panics on a malformed configuration.
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
    pub requests_per_minute: u64,
    pub burst: u64,
}

impl RateLimitSettings {
    pub fn build_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.requests_per_minute, self.burst)
    }
}

/// Thread-safe token-bucket rate limiter.
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
    pub fn from_config(settings: &RateLimitSettings) -> Self {
        settings.build_limiter()
    }

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

    /// Attempts to consume one token; `Err` if the rate limit is exceeded.
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
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

impl MetricsSettings {
    /// Resolves `host:port` to the metrics socket address; panics on a malformed configuration.
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

/// TLS configuration settings (PEM cert/key paths).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsSettings {
    pub enabled: bool,
    pub cert_path: String,
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
    /// Loads configuration by merging, in order of precedence: `SERVER_`-prefixed environment
    /// variables, the TOML file at `SERVER_CONFIG_PATH` (default `config/server.toml`), a `.env`
    /// file, then built-in defaults. Missing files are skipped silently.
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

    /// Validates the configuration (TLS paths exist, non-zero rate limits) for production use.
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
