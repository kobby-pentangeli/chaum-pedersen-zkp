use std::time::Duration;

use chaum_pedersen::Ristretto255;
use chaum_pedersen::proto::auth_service_server::AuthServiceServer;
use chaum_pedersen::server::{AuthServiceImpl, ServerConfig, ServerState};
use tokio::{signal, time};
use tonic::transport::Server;
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

    info!("Server configuration loaded");
    info!("  Listen address: {}", config.server.addr());
    info!("  Metrics enabled: {}", config.metrics.enabled);
    if config.metrics.enabled {
        info!("  Metrics address: {}", config.metrics.addr());
    }

    let state = ServerState::<Ristretto255>::new();
    let service = AuthServiceImpl::new(state.clone());

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired_challenges().await;
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

    let addr = config.server.addr();
    info!("Starting gRPC server on {addr}");

    Server::builder()
        .add_service(AuthServiceServer::new(service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("Server shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
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

    info!("Initiating graceful shutdown");
}
