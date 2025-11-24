use std::io::{self, Write};

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chaum_pedersen::proto::auth_service_client::AuthServiceClient;
use chaum_pedersen::proto::{
    BatchRegistrationRequest, BatchVerificationRequest, ChallengeRequest, RegistrationRequest,
    VerificationRequest,
};
use chaum_pedersen::{
    Parameters, Prover, Ristretto255, Scalar, SecureRng, Statement, Transcript, Witness,
};
use clap::Parser;
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tonic::transport::Channel;

#[derive(Parser, Debug)]
#[command(name = "client")]
#[command(about = "Chaum-Pedersen interactive authentication client", long_about = None)]
#[command(version)]
struct Args {
    /// Server address to connect to
    #[arg(
        short,
        long,
        env = "SERVER_ADDR",
        default_value = "http://127.0.0.1:50051"
    )]
    server: String,
}

enum Command {
    Register(String, String),
    BatchRegister(Vec<String>, Vec<String>),
    Login(String, String),
    BatchLogin(Vec<String>, Vec<String>),
    Status,
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

        let parts = input.splitn(4, ' ').collect::<Vec<&str>>();
        let cmd = parts[0].to_lowercase();

        match cmd.as_str() {
            "/register" | "/r" => {
                if parts.len() < 3 {
                    return Command::Unknown("Usage: /register <user_id> <password>".to_string());
                }
                Command::Register(parts[1].to_string(), parts[2].to_string())
            }
            "/batch-register" | "/br" => {
                if parts.len() < 3 {
                    return Command::Unknown(
                        "Usage: /batch-register <user1,user2,...> <pass1,pass2,...>".to_string(),
                    );
                }
                let users: Vec<String> =
                    parts[1].split(',').map(|s| s.trim().to_string()).collect();
                let passwords: Vec<String> =
                    parts[2].split(',').map(|s| s.trim().to_string()).collect();
                if users.len() != passwords.len() {
                    return Command::Unknown(format!(
                        "Number of users ({}) must match number of passwords ({})",
                        users.len(),
                        passwords.len()
                    ));
                }
                Command::BatchRegister(users, passwords)
            }
            "/login" | "/l" => {
                if parts.len() < 3 {
                    return Command::Unknown("Usage: /login <user_id> <password>".to_string());
                }
                Command::Login(parts[1].to_string(), parts[2].to_string())
            }
            "/batch-login" | "/bl" => {
                if parts.len() < 3 {
                    return Command::Unknown(
                        "Usage: /batch-login <user1,user2,...> <pass1,pass2,...>".to_string(),
                    );
                }
                let users: Vec<String> =
                    parts[1].split(',').map(|s| s.trim().to_string()).collect();
                let passwords: Vec<String> =
                    parts[2].split(',').map(|s| s.trim().to_string()).collect();
                if users.len() != passwords.len() {
                    return Command::Unknown(format!(
                        "Number of users ({}) must match number of passwords ({})",
                        users.len(),
                        passwords.len()
                    ));
                }
                Command::BatchLogin(users, passwords)
            }
            "/status" | "/st" => Command::Status,
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
        "|       Chaum-Pedersen ZKP Authentication Client          |",
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
    println!("  /register <user> <pass>              - Register a new user");
    println!("  /login <user> <pass>                 - Authenticate (prove knowledge of password)");
    println!("  /batch-register <u1,u2> <p1,p2>      - Batch register multiple users");
    println!("  /batch-login <u1,u2> <p1,p2>         - Batch authenticate multiple users");
    println!("  /status                              - Show connection status");
    println!("  /help                                - Show this help message");
    println!("  /quit or /exit                       - Exit gracefully");
    println!();
    println_colored(Color::DarkGrey, "Examples:");
    println_colored(Color::DarkGrey, "  /register alice secretpass123");
    println_colored(Color::DarkGrey, "  /login alice secretpass123");
    println_colored(Color::DarkGrey, "  /batch-register alice,bob pass1,pass2");
    println_colored(Color::DarkGrey, "  /batch-login alice,bob pass1,pass2");
    println!();
}

fn display_prompt(server: &str) {
    print_colored(Color::Green, &format!("zkp-client@{server}"));
    print_colored(Color::White, "> ");
    io::stdout().flush().ok();
}

fn password_to_scalar(password: &str, user_id: &str) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"chaum-pedersen-v1.0.0-");
    hasher.update(user_id.as_bytes());
    let hash_result = hasher.finalize();

    let salt = SaltString::encode_b64(&hash_result[..16])
        .unwrap_or_else(|e| panic!("Salt encoding failed: {e}"));

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap_or_else(|e| panic!("Password hashing failed: {e}"));

    let hash_bytes = hash
        .hash
        .unwrap_or_else(|| unreachable!("Hash always present"));
    let hash_bytes = hash_bytes.as_bytes();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash_bytes[..32]);

    Ristretto255::scalar_from_bytes(&scalar_bytes)
        .unwrap_or_else(|e| panic!("Failed to create scalar from password hash: {e}"))
}

async fn do_register(
    client: &mut AuthServiceClient<Channel>,
    user: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let x = password_to_scalar(password, user);
    let params = Parameters::new();
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
    let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

    let request = tonic::Request::new(RegistrationRequest {
        user_id: user.to_string(),
        y1: y1_bytes,
        y2: y2_bytes,
    });

    let response = client.register(request).await?.into_inner();

    if response.success {
        println_colored(Color::Green, &format!("Registered: {}", response.message));
    } else {
        println_colored(Color::Red, &format!("Failed: {}", response.message));
    }
    Ok(())
}

async fn do_login(
    client: &mut AuthServiceClient<Channel>,
    user: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let challenge_req = tonic::Request::new(ChallengeRequest {
        user_id: user.to_string(),
    });

    let challenge_resp = client.create_challenge(challenge_req).await?.into_inner();
    println_colored(
        Color::DarkGrey,
        &format!(
            "  Challenge received, expires: {}",
            challenge_resp.expires_at
        ),
    );

    let x = password_to_scalar(password, user);
    let params = Parameters::new();
    let witness = Witness::new(x);
    let prover = Prover::new(params, witness);

    let mut rng = SecureRng::new();
    let mut transcript = Transcript::new();
    transcript.append_context(&challenge_resp.challenge_id);

    let proof = prover.prove_with_transcript(&mut rng, &mut transcript)?;
    let proof_bytes = proof.to_bytes()?;

    let verify_req = tonic::Request::new(VerificationRequest {
        user_id: user.to_string(),
        challenge_id: challenge_resp.challenge_id,
        proof: proof_bytes,
    });

    let verify_resp = client.verify_proof(verify_req).await?.into_inner();

    if verify_resp.success {
        println_colored(
            Color::Green,
            &format!("Authenticated: {}", verify_resp.message),
        );
        if let Some(token) = verify_resp.session_token {
            println_colored(Color::Cyan, &format!("  Session token: {token}"));
        }
    } else {
        println_colored(Color::Red, &format!("Failed: {}", verify_resp.message));
    }
    Ok(())
}

async fn do_batch_register(
    client: &mut AuthServiceClient<Channel>,
    users: &[String],
    passwords: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let batch_size = users.len();
    println_colored(
        Color::White,
        &format!("Generating statements for {batch_size} users..."),
    );

    let mut y1_values = Vec::with_capacity(batch_size);
    let mut y2_values = Vec::with_capacity(batch_size);

    for (i, user) in users.iter().enumerate() {
        let x = password_to_scalar(&passwords[i], user);
        let params = Parameters::new();
        let witness = Witness::new(x);
        let statement = Statement::from_witness(&params, &witness);

        y1_values.push(Ristretto255::element_to_bytes(statement.y1()));
        y2_values.push(Ristretto255::element_to_bytes(statement.y2()));
    }

    let request = tonic::Request::new(BatchRegistrationRequest {
        user_ids: users.to_vec(),
        y1_values,
        y2_values,
    });

    let response = client.register_batch(request).await?.into_inner();

    let mut success_count = 0;
    for (i, result) in response.results.iter().enumerate() {
        if result.success {
            success_count += 1;
            println_colored(
                Color::Green,
                &format!("  [OK] {}: {}", users[i], result.message),
            );
        } else {
            println_colored(
                Color::Red,
                &format!("  [FAIL] {}: {}", users[i], result.message),
            );
        }
    }

    println_colored(
        Color::Cyan,
        &format!(
            "Batch complete: {}/{} registered",
            success_count, batch_size
        ),
    );
    Ok(())
}

async fn do_batch_login(
    client: &mut AuthServiceClient<Channel>,
    users: &[String],
    passwords: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let batch_size = users.len();
    println_colored(
        Color::White,
        &format!("Generating proofs for {batch_size} users..."),
    );

    let mut challenge_ids = Vec::with_capacity(batch_size);
    let mut proofs = Vec::with_capacity(batch_size);

    for (i, user) in users.iter().enumerate() {
        let challenge_req = tonic::Request::new(ChallengeRequest {
            user_id: user.to_string(),
        });
        let challenge_resp = client.create_challenge(challenge_req).await?.into_inner();
        challenge_ids.push(challenge_resp.challenge_id.clone());

        let x = password_to_scalar(&passwords[i], user);
        let params = Parameters::new();
        let witness = Witness::new(x);
        let prover = Prover::new(params, witness);

        let mut rng = SecureRng::new();
        let mut transcript = Transcript::new();
        transcript.append_context(&challenge_resp.challenge_id);

        let proof = prover.prove_with_transcript(&mut rng, &mut transcript)?;
        proofs.push(proof.to_bytes()?);
    }

    let request = tonic::Request::new(BatchVerificationRequest {
        user_ids: users.to_vec(),
        challenge_ids,
        proofs,
    });

    let response = client.verify_proof_batch(request).await?.into_inner();

    let mut success_count = 0;
    for (i, result) in response.results.iter().enumerate() {
        if result.success {
            success_count += 1;
            println_colored(
                Color::Green,
                &format!("  [OK] {}: {}", users[i], result.message),
            );
            if let Some(token) = &result.session_token {
                println_colored(Color::Cyan, &format!("       Token: {token}"));
            }
        } else {
            println_colored(
                Color::Red,
                &format!("  [FAIL] {}: {}", users[i], result.message),
            );
        }
    }

    println_colored(
        Color::Cyan,
        &format!(
            "Batch complete: {}/{} authenticated",
            success_count, batch_size
        ),
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    display_banner();

    println_colored(Color::White, &format!("Connecting to {}...", args.server));

    let mut client = match AuthServiceClient::connect(args.server.clone()).await {
        Ok(c) => {
            println_colored(Color::Green, "Connected successfully");
            c
        }
        Err(e) => {
            println_colored(Color::Red, &format!("Connection failed: {e}"));
            return Err(e.into());
        }
    };

    println!();
    println_colored(
        Color::Yellow,
        "Type /help for available commands or /quit to exit",
    );
    println!();

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        display_prompt(&args.server);

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
            Command::Register(user, password) => {
                if let Err(e) = do_register(&mut client, &user, &password).await {
                    println_colored(Color::Red, &format!("Error: {e}"));
                }
            }
            Command::BatchRegister(users, passwords) => {
                if let Err(e) = do_batch_register(&mut client, &users, &passwords).await {
                    println_colored(Color::Red, &format!("Error: {e}"));
                }
            }
            Command::Login(user, password) => {
                if let Err(e) = do_login(&mut client, &user, &password).await {
                    println_colored(Color::Red, &format!("Error: {e}"));
                }
            }
            Command::BatchLogin(users, passwords) => {
                if let Err(e) = do_batch_login(&mut client, &users, &passwords).await {
                    println_colored(Color::Red, &format!("Error: {e}"));
                }
            }
            Command::Status => {
                println!();
                println_colored(Color::Cyan, "Client Status:");
                println_colored(Color::White, &format!("  Server: {}", args.server));
                println_colored(Color::White, "  Connection: active");
                println!();
            }
            Command::Help => {
                display_help();
            }
            Command::Quit => {
                println!();
                println_colored(Color::Green, "Goodbye!");
                println!();
                break;
            }
            Command::Unknown(msg) => {
                if !msg.is_empty() {
                    println_colored(Color::Red, &msg);
                }
            }
        }
    }

    Ok(())
}
