use std::time::Duration;

use chaum_pedersen::Ristretto255;
use chaum_pedersen::proto::auth_service_server::AuthServiceServer;
use chaum_pedersen::verifier::{AuthServiceImpl, RateLimiter, ServerConfig, ServerState};
use tokio::{signal, time};
use tonic::transport::Server;
use tonic_health::server::{HealthReporter, health_reporter};
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Chaum-Pedersen authentication server");

    let config = ServerConfig::from_env().unwrap_or_else(|e| {
        error!("Failed to load configuration: {e}");
        info!("Using default configuration");
        ServerConfig::default()
    });

    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {e}");
        return Err(format!("Invalid configuration: {e}").into());
    }

    info!("Server configuration loaded and validated");
    info!("  Listen address: {}", config.addr());
    info!("  Metrics enabled: {}", config.metrics.enabled);
    if config.metrics.enabled {
        info!("  Metrics address: {}", config.metrics.addr());
    }

    let state = ServerState::<Ristretto255>::new();
    let rate_limiter = RateLimiter::from_config(&config.rate_limit);
    let service = AuthServiceImpl::new(state.clone(), rate_limiter);

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        loop {
            let state_clone = cleanup_state.clone();
            let cleanup_handle = tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    state_clone.cleanup_expired_challenges().await;
                    state_clone.cleanup_expired_sessions().await;
                }
            });

            match cleanup_handle.await {
                Ok(()) => {
                    error!("Cleanup task terminated unexpectedly, restarting...");
                }
                Err(e) => {
                    error!("Cleanup task panicked: {:?}, restarting...", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    if config.metrics.enabled {
        let metrics_addr = config.metrics.addr();
        tokio::spawn(async move {
            if let Err(e) = metrics_exporter_prometheus::PrometheusBuilder::new()
                .with_http_listener(metrics_addr)
                .install()
            {
                error!("Failed to start metrics server: {e}");
            } else {
                info!("Metrics server started on {metrics_addr}");
            }
        });
    }

    let (mut health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthServiceImpl<Ristretto255>>>()
        .await;

    let addr = config.addr();
    info!("Starting gRPC server on {addr}");
    info!(
        "  Rate limit: {} requests/min, burst: {}",
        config.rate_limit.requests_per_minute, config.rate_limit.burst
    );
    info!("  Health check endpoint: enabled");
    info!(
        "  TLS: {}",
        if config.tls.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    let shutdown_reporter = health_reporter.clone();
    let mut server_builder = Server::builder();

    if config.tls.enabled {
        let cert = tokio::fs::read(&config.tls.cert_path).await.map_err(|e| {
            format!(
                "Failed to read TLS certificate from {}: {e}",
                config.tls.cert_path
            )
        })?;
        let key = tokio::fs::read(&config.tls.key_path).await.map_err(|e| {
            format!(
                "Failed to read TLS private key from {}: {e}",
                config.tls.key_path
            )
        })?;

        let identity = tonic::transport::Identity::from_pem(cert, key);
        let tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);

        server_builder = Server::builder()
            .tls_config(tls_config)
            .map_err(|e| format!("Failed to configure TLS: {e}"))?;

        info!("  TLS certificate: {}", config.tls.cert_path);
        info!("  TLS private key: {}", config.tls.key_path);
    }

    server_builder
        .add_service(health_service)
        .add_service(AuthServiceServer::new(service))
        .serve_with_shutdown(addr, shutdown_signal(shutdown_reporter))
        .await?;

    info!("Server shutdown complete");
    Ok(())
}

async fn shutdown_signal(mut health_reporter: HealthReporter) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received terminate signal");
        },
    }

    health_reporter
        .set_not_serving::<AuthServiceServer<AuthServiceImpl<Ristretto255>>>()
        .await;

    info!("Initiating graceful shutdown (allowing in-flight requests to complete)");
    info!("Press Ctrl+C again to force immediate shutdown");

    let graceful_timeout = tokio::time::sleep(Duration::from_secs(30));
    let forced_shutdown = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install second Ctrl+C handler");
    };

    tokio::select! {
        _ = graceful_timeout => {
            info!("Graceful shutdown timeout reached after 30 seconds");
        },
        _ = forced_shutdown => {
            info!("Forced shutdown requested");
        },
    }
}
