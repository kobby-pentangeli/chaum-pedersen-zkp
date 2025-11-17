use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Server configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server listening settings.
    pub server: ServerSettings,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitSettings,
    /// Metrics exporter configuration.
    pub metrics: MetricsSettings,
}

/// Server listening settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Hostname or IP address to bind to.
    pub host: String,
    /// Port number to listen on.
    pub port: u16,
}

impl ServerSettings {
    /// Converts host and port into a socket address.
    pub fn addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|_| unreachable!("Invalid host:port configuration"))
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
    pub fn addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|_| unreachable!("Invalid metrics host:port configuration"))
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                host: "127.0.0.1".to_string(),
                port: 50051,
            },
            rate_limit: RateLimitSettings {
                requests_per_minute: 100,
                burst: 10,
            },
            metrics: MetricsSettings {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 9090,
            },
        }
    }
}

impl ServerConfig {
    /// Loads configuration from TOML file and environment variables.
    ///
    /// Configuration priority: environment variables > TOML file > defaults.
    #[allow(clippy::result_large_err)]
    pub fn from_env() -> figment::error::Result<Self> {
        use figment::Figment;
        use figment::providers::{Env, Format, Toml};

        Figment::new()
            .merge(Toml::file("config/server.toml").nested())
            .merge(Env::prefixed("SERVER_").split("_"))
            .extract()
    }
}
