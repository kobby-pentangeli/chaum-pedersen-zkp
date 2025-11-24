//! Authentication system example using Chaum-Pedersen protocol.
//!
//! This example demonstrates a zero-knowledge authentication system where:
//! - Users register with a public statement (y1, y2) derived from their secret
//! - Server creates authentication challenges
//! - Users prove knowledge of their secret without revealing it
//! - Server verifies the proof to authenticate the user
//! - Replay attacks are prevented by binding proofs to challenge IDs

use std::collections::HashMap;

use chaum_pedersen::{
    Parameters, Proof, Prover, Ristretto255, SecureRng, Statement, Transcript, Verifier, Witness,
};

/// Simple authentication server that stores user statements and manages challenges.
struct AuthServer {
    params: Parameters,
    users: HashMap<String, Statement>,
    active_challenges: HashMap<String, String>,
    challenge_counter: u64,
}

impl AuthServer {
    fn new() -> Self {
        Self {
            params: Parameters::new(),
            users: HashMap::new(),
            active_challenges: HashMap::new(),
            challenge_counter: 0,
        }
    }

    fn register(&mut self, username: String, statement: Statement) {
        println!("  Server: Registering user '{}'", username);
        self.users.insert(username, statement);
    }

    fn create_challenge(&mut self, username: &str) -> Option<String> {
        if !self.users.contains_key(username) {
            println!("  Server: User '{}' not found", username);
            return None;
        }

        self.challenge_counter += 1;
        let challenge_id = format!("challenge-{}-{}", username, self.challenge_counter);
        println!(
            "  Server: Created challenge '{}' for user '{}'",
            challenge_id, username
        );
        self.active_challenges
            .insert(username.to_string(), challenge_id.clone());
        Some(challenge_id)
    }

    fn verify_authentication(&mut self, username: &str, challenge_id: &str, proof: &Proof) -> bool {
        if let Some(expected_challenge) = self.active_challenges.get(username) {
            if expected_challenge != challenge_id {
                println!("  Server: Challenge mismatch for user '{}'", username);
                return false;
            }
        } else {
            println!("  Server: No active challenge for user '{}'", username);
            return false;
        }

        if let Some(statement) = self.users.get(username) {
            let mut transcript = Transcript::new();
            transcript.append_context(challenge_id.as_bytes());

            let verifier = Verifier::new(self.params.clone(), statement.clone());
            let result = verifier.verify_with_transcript(proof, &mut transcript);

            self.active_challenges.remove(username);

            match result {
                Ok(()) => {
                    println!("  Server: Authentication successful for '{}'", username);
                    true
                }
                Err(_) => {
                    println!("  Server: Authentication failed for '{}'", username);
                    false
                }
            }
        } else {
            println!("  Server: User '{}' not found", username);
            false
        }
    }
}

/// Simple authentication client that manages user credentials.
struct AuthClient {
    params: Parameters,
    witness: Witness,
}

impl AuthClient {
    fn new() -> Self {
        let params = Parameters::new();
        let mut rng = SecureRng::new();

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        Self { params, witness }
    }

    fn get_registration_statement(&self) -> Statement {
        Statement::from_witness(&self.params, &self.witness)
    }

    fn authenticate(&self, challenge_id: &str) -> Proof {
        let mut rng = SecureRng::new();
        let mut transcript = Transcript::new();
        transcript.append_context(challenge_id.as_bytes());

        let prover = Prover::new(self.params.clone(), self.witness.clone());
        prover
            .prove_with_transcript(&mut rng, &mut transcript)
            .expect("Proof generation should succeed")
    }
}

fn main() {
    println!("Chaum-Pedersen Zero-Knowledge Protocol: Authentication System Example\n");
    println!("==============================================\n");

    println!("Phase 1: User Registration");
    println!("---------------------------");

    let client_alice = AuthClient::new();
    let alice_statement = client_alice.get_registration_statement();

    let mut server = AuthServer::new();
    server.register("alice".to_string(), alice_statement);
    println!();

    println!("Phase 2: Authentication Flow");
    println!("-----------------------------");

    println!("Step 1: Alice requests authentication");
    let challenge = server
        .create_challenge("alice")
        .expect("Challenge should be created");
    println!();

    println!("Step 2: Alice generates proof");
    println!("  Client: Generating proof for challenge '{}'", challenge);
    let proof = client_alice.authenticate(&challenge);
    println!("  Client: Proof generated");
    println!();

    println!("Step 3: Server verifies proof");
    let authenticated = server.verify_authentication("alice", &challenge, &proof);
    println!();

    if authenticated {
        println!("Alice successfully authenticated!");
    } else {
        println!("Authentication failed!");
    }

    println!("\n==============================================");
    println!("Replay Attack Prevention Demo");
    println!("==============================================\n");

    println!("Attempting to reuse the same proof...");
    let challenge2 = server
        .create_challenge("alice")
        .expect("Challenge should be created");

    let replay_attempt = server.verify_authentication("alice", &challenge2, &proof);
    println!();

    if replay_attempt {
        println!("SECURITY FAILURE: Replay attack succeeded!");
    } else {
        println!("Replay attack prevented successfully!");
        println!("The proof is bound to the specific challenge ID");
    }

    println!("\n==============================================");
    println!("Wrong Secret Demo");
    println!("==============================================\n");

    println!("Creating a different client with different secret...");
    let wrong_client = AuthClient::new();

    let challenge3 = server
        .create_challenge("alice")
        .expect("Challenge should be created");

    println!("Attempting authentication with different secret...");
    let wrong_proof = wrong_client.authenticate(&challenge3);

    let wrong_attempt = server.verify_authentication("alice", &challenge3, &wrong_proof);
    println!();

    if wrong_attempt {
        println!("SECURITY FAILURE: Wrong secret accepted!");
    } else {
        println!("Wrong secret correctly rejected!");
    }
}
