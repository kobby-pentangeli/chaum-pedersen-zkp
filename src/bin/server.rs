use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chaum_pedersen::proto::auth_service_server::AuthServiceServer;
use chaum_pedersen::verifier::{AuthServiceImpl, RateLimiter, ServerConfig, ServerState};
use clap::Parser;
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;
use tokio::{signal, time};
use tonic::transport::Server;
use tonic_health::server::{HealthReporter, health_reporter};
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser, Debug)]
#[command(name = "server")]
#[command(about = "Chaum-Pedersen interactive authentication server", long_about = None)]
#[command(version)]
struct Args {
    /// Host to bind to
    #[arg(short = 'H', long, env = "SERVER_HOST", default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(short, long, env = "SERVER_PORT", default_value = "50051")]
    port: u16,

    /// Enable metrics endpoint
    #[arg(long, env = "METRICS_ENABLED", default_value = "false")]
    metrics: bool,

    /// Metrics port
    #[arg(long, env = "METRICS_PORT", default_value = "9090")]
    metrics_port: u16,

    /// Rate limit requests per minute
    #[arg(long, env = "RATE_LIMIT_RPM", default_value = "100")]
    rate_limit: u64,

    /// Rate limit burst
    #[arg(long, env = "RATE_LIMIT_BURST", default_value = "50")]
    rate_burst: u64,
}

enum Command {
    Status,
    Users,
    Sessions,
    Challenges,
    Cleanup,
    Help,
    Quit,
    Unknown(String),
}

impl Command {
    fn parse(input: &str) -> Self {
        let input = input.trim();

        if input.is_empty() {
            return Command::Unknown(String::new());
        }

        if !input.starts_with('/') {
            return Command::Unknown(
                "Commands must start with '/'. Type /help for available commands.".to_string(),
            );
        }

        let cmd = input.split_whitespace().next().unwrap_or("").to_lowercase();

        match cmd.as_str() {
            "/status" | "/st" => Command::Status,
            "/users" | "/u" => Command::Users,
            "/sessions" | "/s" => Command::Sessions,
            "/challenges" | "/c" => Command::Challenges,
            "/cleanup" | "/gc" => Command::Cleanup,
            "/help" | "/h" | "/?" => Command::Help,
            "/quit" | "/exit" | "/q" => Command::Quit,
            _ => Command::Unknown(format!(
                "Unknown command: {cmd}. Type /help for available commands."
            )),
        }
    }
}

fn print_colored(color: Color, text: &str) {
    let mut stdout = io::stdout();
    execute!(stdout, SetForegroundColor(color), Print(text), ResetColor).ok();
    stdout.flush().ok();
}

fn println_colored(color: Color, text: &str) {
    print_colored(color, text);
    println!();
}

fn display_banner() {
    println!();
    println_colored(
        Color::Cyan,
        "+---------------------------------------------------------+",
    );
    println_colored(
        Color::Cyan,
        "|       Chaum-Pedersen ZKP Authentication Server          |",
    );
    println_colored(
        Color::Cyan,
        "+---------------------------------------------------------+",
    );
    println!();
}

fn display_help() {
    println!();
    println_colored(Color::Yellow, "Available Commands:");
    println!();
    println!("  /status              - Show server status and configuration");
    println!("  /users               - List registered users count");
    println!("  /sessions            - List active sessions count");
    println!("  /challenges          - List pending challenges count");
    println!("  /cleanup             - Force cleanup of expired state");
    println!("  /help                - Show this help message");
    println!("  /quit or /exit       - Initiate graceful shutdown");
    println!();
}

fn display_prompt(addr: &str) {
    print_colored(Color::Green, &format!("zkp-server@{addr}"));
    print_colored(Color::White, "> ");
    io::stdout().flush().ok();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    display_banner();

    let config = ServerConfig::from_env().unwrap_or_else(|e| {
        error!("Failed to load configuration: {e}");
        info!("Using default configuration");
        ServerConfig::default()
    });

    if let Err(e) = config.validate() {
        println_colored(Color::Red, &format!("Configuration validation failed: {e}"));
        return Err(format!("Invalid configuration: {e}").into());
    }

    let state = ServerState::new();
    let rate_limiter = RateLimiter::new(args.rate_limit, args.rate_burst);
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

    if args.metrics {
        let metrics_addr = format!("{}:{}", args.host, args.metrics_port).parse::<SocketAddr>()?;
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
        .set_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    let addr = format!("{}:{}", args.host, args.port).parse::<SocketAddr>()?;
    let addr_str = addr.to_string();

    println_colored(Color::Green, &format!("Server starting on {addr}"));
    println_colored(
        Color::White,
        &format!(
            "  Rate limit: {} req/min, burst: {}",
            args.rate_limit, args.rate_burst
        ),
    );
    println_colored(
        Color::White,
        &format!(
            "  Metrics: {}",
            if args.metrics { "enabled" } else { "disabled" }
        ),
    );
    println_colored(Color::White, "  Health check: enabled");
    println!();
    println_colored(
        Color::Yellow,
        "Type /help for available commands or /quit to exit",
    );
    println!();

    let shutdown_reporter = health_reporter.clone();
    let shutdown_flag = Arc::new(Mutex::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(health_service)
            .add_service(AuthServiceServer::new(service))
            .serve_with_shutdown(
                addr,
                shutdown_signal(shutdown_reporter, shutdown_flag_clone),
            )
            .await
    });

    let repl_state = state.clone();
    let repl_shutdown_flag = shutdown_flag.clone();

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        display_prompt(&addr_str);

        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                println_colored(Color::Red, &format!("Error reading input: {e}"));
                continue;
            }
        }

        let command = Command::parse(&line);

        match command {
            Command::Status => {
                let user_count = repl_state.user_count().await;
                let session_count = repl_state.session_count().await;
                let challenge_count = repl_state.challenge_count().await;

                println!();
                println_colored(Color::Cyan, "Server Status:");
                println_colored(Color::White, &format!("  Address: {addr}"));
                println_colored(
                    Color::White,
                    &format!("  Rate limit: {} req/min", args.rate_limit),
                );
                println_colored(Color::White, &format!("  Burst: {}", args.rate_burst));
                println_colored(
                    Color::White,
                    &format!(
                        "  Metrics: {}",
                        if args.metrics { "enabled" } else { "disabled" }
                    ),
                );
                println!();
                println_colored(Color::Cyan, "State:");
                println_colored(Color::White, &format!("  Registered users: {user_count}"));
                println_colored(Color::White, &format!("  Active sessions: {session_count}"));
                println_colored(
                    Color::White,
                    &format!("  Pending challenges: {challenge_count}"),
                );
                println!();
            }
            Command::Users => {
                let count = repl_state.user_count().await;
                println_colored(Color::Cyan, &format!("Registered users: {count}"));
            }
            Command::Sessions => {
                let count = repl_state.session_count().await;
                println_colored(Color::Cyan, &format!("Active sessions: {count}"));
            }
            Command::Challenges => {
                let count = repl_state.challenge_count().await;
                println_colored(Color::Cyan, &format!("Pending challenges: {count}"));
            }
            Command::Cleanup => {
                println_colored(Color::White, "Running cleanup...");
                repl_state.cleanup_expired_challenges().await;
                repl_state.cleanup_expired_sessions().await;
                println_colored(Color::Green, "Cleanup complete");
            }
            Command::Help => {
                display_help();
            }
            Command::Quit => {
                println!();
                println_colored(Color::Yellow, "Initiating graceful shutdown...");
                *repl_shutdown_flag.lock().await = true;
                break;
            }
            Command::Unknown(msg) => {
                if !msg.is_empty() {
                    println_colored(Color::Red, &msg);
                }
            }
        }
    }

    match server_handle.await {
        Ok(Ok(())) => {
            println_colored(Color::Green, "Server shutdown complete. Goodbye!");
        }
        Ok(Err(e)) => {
            println_colored(Color::Red, &format!("Server error: {e}"));
        }
        Err(e) => {
            println_colored(Color::Red, &format!("Server task panicked: {e}"));
        }
    }

    println!();
    Ok(())
}

async fn shutdown_signal(mut health_reporter: HealthReporter, shutdown_flag: Arc<Mutex<bool>>) {
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

    let repl_quit = async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if *shutdown_flag.lock().await {
                break;
            }
        }
    };

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received terminate signal");
        },
        _ = repl_quit => {
            info!("Shutdown requested via REPL");
        },
    }

    health_reporter
        .set_not_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    info!("Initiating graceful shutdown (allowing in-flight requests to complete)");

    tokio::time::sleep(Duration::from_secs(2)).await;
}
