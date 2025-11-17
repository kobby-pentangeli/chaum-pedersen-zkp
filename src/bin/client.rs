use argon2::{Argon2, PasswordHasher};
use chaum_pedersen::proto::auth_service_client::AuthServiceClient;
use chaum_pedersen::proto::{ChallengeRequest, RegistrationRequest, VerificationRequest};
use chaum_pedersen::{
    Group, Parameters, Prover, Ristretto255, SecureRng, Statement, Transcript, Witness,
};
use clap::{Parser, Subcommand};

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

    Login {
        #[arg(short, long)]
        user: String,

        #[arg(short, long)]
        password: String,
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

            let request = tonic::Request::new(RegistrationRequest {
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

        Commands::Login { user, password } => {
            println!("Authenticating user '{user}'...");

            let request = tonic::Request::new(ChallengeRequest {
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

            let request = tonic::Request::new(VerificationRequest {
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
    }

    Ok(())
}
