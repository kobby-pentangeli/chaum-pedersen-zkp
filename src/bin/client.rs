use std::time::Instant;

use argon2::{Argon2, PasswordHasher};
use chaum_pedersen::proto::auth_service_client::AuthServiceClient;
use chaum_pedersen::proto::{
    BatchRegistrationRequest, BatchVerificationRequest, ChallengeRequest, RegistrationRequest,
    VerificationRequest,
};
use chaum_pedersen::{
    Group, Parameters, Prover, Ristretto255, SecureRng, Statement, Transcript, Witness,
};
use clap::{Parser, Subcommand};
use tonic::Request;

#[derive(Parser)]
#[command(name = "client")]
#[command(about = "Chaum-Pedersen authentication client", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "http://127.0.0.1:50051")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register {
        #[arg(short, long)]
        user: String,

        #[arg(short, long)]
        password: String,
    },

    BatchRegister {
        #[arg(short, long, value_delimiter = ',', help = "Comma-separated user IDs")]
        users: Vec<String>,

        #[arg(
            short,
            long,
            value_delimiter = ',',
            help = "Comma-separated passwords (must match order of users)"
        )]
        passwords: Vec<String>,
    },

    Login {
        #[arg(short, long)]
        user: String,

        #[arg(short, long)]
        password: String,
    },

    BatchLogin {
        #[arg(short, long, value_delimiter = ',', help = "Comma-separated user IDs")]
        users: Vec<String>,

        #[arg(
            short,
            long,
            value_delimiter = ',',
            help = "Comma-separated passwords (must match order of users)"
        )]
        passwords: Vec<String>,
    },
}

fn password_to_scalar(password: &str, user_id: &str) -> <Ristretto255 as Group>::Scalar {
    use argon2::password_hash::SaltString;
    use sha2::{Digest, Sha256};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut client = AuthServiceClient::connect(cli.server.clone()).await?;

    match cli.command {
        Commands::Register { user, password } => {
            println!("Registering user '{user}'...");

            let x = password_to_scalar(&password, &user);
            let params = Parameters::<Ristretto255>::new();
            let witness = Witness::new(x);
            let statement = Statement::from_witness(&params, &witness);

            let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
            let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

            let request = Request::new(RegistrationRequest {
                user_id: user.clone(),
                y1: y1_bytes,
                y2: y2_bytes,
                group_name: "Ristretto255".to_string(),
            });

            let response = client.register(request).await?;
            let response = response.into_inner();

            if response.success {
                println!("Success: {}", response.message);
            } else {
                eprintln!("Failed: {}", response.message);
                std::process::exit(1);
            }
        }

        Commands::BatchRegister { users, passwords } => {
            if users.is_empty() {
                eprintln!("Error: No users provided");
                std::process::exit(1);
            }

            if users.len() != passwords.len() {
                eprintln!(
                    "Error: Number of users ({}) does not match number of passwords ({})",
                    users.len(),
                    passwords.len()
                );
                std::process::exit(1);
            }

            let batch_size = users.len();
            println!("Batch registering {batch_size} users...");
            println!();

            let mut y1_values = Vec::with_capacity(batch_size);
            let mut y2_values = Vec::with_capacity(batch_size);

            let start_total = Instant::now();

            for (i, user) in users.iter().enumerate() {
                print!(
                    "[{}/{}] Generating statement for '{}'... ",
                    i + 1,
                    batch_size,
                    user
                );

                let x = password_to_scalar(&passwords[i], user);
                let params = Parameters::<Ristretto255>::new();
                let witness = Witness::new(x);
                let statement = Statement::from_witness(&params, &witness);

                let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
                let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

                y1_values.push(y1_bytes);
                y2_values.push(y2_bytes);

                println!("✓");
            }

            println!();
            println!("Submitting batch registration request for {batch_size} users...");

            let batch_start = Instant::now();

            let request = Request::new(BatchRegistrationRequest {
                user_ids: users.clone(),
                y1_values,
                y2_values,
                group_name: "Ristretto255".to_string(),
            });

            let response = client.register_batch(request).await?;
            let results = response.into_inner().results;

            let batch_duration = batch_start.elapsed();
            let total_duration = start_total.elapsed();

            println!("Batch registration completed in {:?}", batch_duration);
            println!();

            let mut success_count = 0;
            let mut failure_count = 0;

            println!("Results:");
            println!("{}", "=".repeat(80));

            for (i, result) in results.iter().enumerate() {
                if result.success {
                    success_count += 1;
                    println!(
                        "[{}/{}] ✓ User '{}': {}",
                        i + 1,
                        batch_size,
                        users[i],
                        result.message
                    );
                } else {
                    failure_count += 1;
                    println!(
                        "[{}/{}] ✗ User '{}': {}",
                        i + 1,
                        batch_size,
                        users[i],
                        result.message
                    );
                }
            }

            println!("{}", "=".repeat(80));
            println!();
            println!("Summary:");
            println!("  Total users:      {batch_size}");
            println!("  Successful:       {success_count}");
            println!("  Failed:           {failure_count}");
            println!("  Batch register:   {:?}", batch_duration);
            println!("  Total time:       {:?}", total_duration);
            println!(
                "  Avg per user:     {:?}",
                total_duration / batch_size as u32
            );

            if failure_count > 0 {
                println!();
                println!("Note: Some registrations failed. Check results above for details.");
                std::process::exit(1);
            }
        }

        Commands::Login { user, password } => {
            println!("Authenticating user '{user}'...");

            let request = Request::new(ChallengeRequest {
                user_id: user.clone(),
            });

            let response = client.create_challenge(request).await?;
            let response = response.into_inner();

            println!("Challenge received, expires at: {}", response.expires_at);

            let x = password_to_scalar(&password, &user);
            let params = Parameters::<Ristretto255>::new();
            let witness = Witness::new(x);
            let prover = Prover::new(params, witness);

            let mut rng = SecureRng::new();
            let mut transcript = Transcript::new();
            transcript.append_context(&response.challenge_id);

            let proof = prover
                .prove_with_transcript(&mut rng, &mut transcript)
                .unwrap_or_else(|e| panic!("Proof generation failed: {e}"));

            let proof_bytes = proof
                .to_bytes()
                .unwrap_or_else(|e| panic!("Proof serialization failed: {e}"));

            let request = Request::new(VerificationRequest {
                user_id: user.clone(),
                challenge_id: response.challenge_id,
                proof: proof_bytes,
            });

            let response = client.verify_proof(request).await?;
            let response = response.into_inner();

            if response.success {
                println!("Success: {}", response.message);
                if let Some(token) = response.session_token {
                    println!("Session token: {token}");
                }
            } else {
                eprintln!("Authentication failed: {}", response.message);
                std::process::exit(1);
            }
        }

        Commands::BatchLogin { users, passwords } => {
            if users.is_empty() {
                eprintln!("Error: No users provided");
                std::process::exit(1);
            }

            if users.len() != passwords.len() {
                eprintln!(
                    "Error: Number of users ({}) does not match number of passwords ({})",
                    users.len(),
                    passwords.len()
                );
                std::process::exit(1);
            }

            let batch_size = users.len();
            println!("Batch authenticating {batch_size} users...");
            println!();

            let mut challenge_ids = Vec::with_capacity(batch_size);
            let mut proofs = Vec::with_capacity(batch_size);

            let start_total = Instant::now();

            for (i, user) in users.iter().enumerate() {
                print!(
                    "[{}/{}] Requesting challenge for '{}'... ",
                    i + 1,
                    batch_size,
                    user
                );

                let request = Request::new(ChallengeRequest {
                    user_id: user.clone(),
                });

                let response = client.create_challenge(request).await?;
                let response = response.into_inner();

                challenge_ids.push(response.challenge_id.clone());
                println!("✓");

                print!(
                    "[{}/{}] Generating proof for '{}'... ",
                    i + 1,
                    batch_size,
                    user
                );

                let x = password_to_scalar(&passwords[i], user);
                let params = Parameters::<Ristretto255>::new();
                let witness = Witness::new(x);
                let prover = Prover::new(params, witness);

                let mut rng = SecureRng::new();
                let mut transcript = Transcript::new();
                transcript.append_context(&response.challenge_id);

                let proof = prover
                    .prove_with_transcript(&mut rng, &mut transcript)
                    .unwrap_or_else(|e| panic!("Proof generation failed: {e}"));

                let proof_bytes = proof
                    .to_bytes()
                    .unwrap_or_else(|e| panic!("Proof serialization failed: {e}"));

                proofs.push(proof_bytes);
                println!("✓");
            }

            println!();
            println!("Submitting batch verification request for {batch_size} proofs...");

            let batch_start = Instant::now();

            let request = Request::new(BatchVerificationRequest {
                user_ids: users.clone(),
                challenge_ids,
                proofs,
            });

            let response = client.verify_proof_batch(request).await?;
            let results = response.into_inner().results;

            let batch_duration = batch_start.elapsed();
            let total_duration = start_total.elapsed();

            println!("Batch verification completed in {:?}", batch_duration);
            println!();

            let mut success_count = 0;
            let mut failure_count = 0;

            println!("Results:");
            println!("{}", "=".repeat(80));

            for (i, result) in results.iter().enumerate() {
                if result.success {
                    success_count += 1;
                    println!(
                        "[{}/{}] ✓ User '{}': {}",
                        i + 1,
                        batch_size,
                        users[i],
                        result.message
                    );
                    if let Some(token) = &result.session_token {
                        println!("       Session token: {}", token);
                    }
                } else {
                    failure_count += 1;
                    println!(
                        "[{}/{}] ✗ User '{}': {}",
                        i + 1,
                        batch_size,
                        users[i],
                        result.message
                    );
                }
            }

            println!("{}", "=".repeat(80));
            println!();
            println!("Summary:");
            println!("  Total users:      {batch_size}");
            println!("  Successful:       {success_count}");
            println!("  Failed:           {failure_count}");
            println!("  Batch verify:     {:?}", batch_duration);
            println!("  Total time:       {:?}", total_duration);
            println!(
                "  Avg per proof:    {:?}",
                total_duration / batch_size as u32
            );

            if failure_count > 0 {
                println!();
                println!("Note: Some authentications failed. Check results above for details.");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
