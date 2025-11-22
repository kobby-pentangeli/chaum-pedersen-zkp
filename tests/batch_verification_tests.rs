#![cfg(all(feature = "server", feature = "client"))]

use chaum_pedersen::proto::auth_service_client::AuthServiceClient;
use chaum_pedersen::proto::auth_service_server::AuthServiceServer;
use chaum_pedersen::proto::{
    BatchRegistrationRequest, BatchVerificationRequest, ChallengeRequest, RegistrationRequest,
};
use chaum_pedersen::verifier::{AuthServiceImpl, RateLimiter, ServerState};
use chaum_pedersen::{Group, Parameters, Prover, Ristretto255, SecureRng, Transcript, Witness};
use tonic::transport::Server;

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let state = ServerState::<Ristretto255>::new();
    let rate_limiter = RateLimiter::new(10000, 10000);
    let service = AuthServiceImpl::new(state, rate_limiter);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_addr = format!("http://{}", addr);

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (server_addr, server_handle)
}

fn generate_proof_for_user(user_id: &str, challenge_id: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rng = SecureRng::new();
    let params = Parameters::<Ristretto255>::new();

    let password = format!("password-{}", user_id);
    let x = derive_scalar_from_password(&password, user_id);
    let witness = Witness::new(x);

    let prover = Prover::new(params.clone(), witness);
    let statement = prover.statement();

    let y1 = Ristretto255::element_to_bytes(statement.y1());
    let y2 = Ristretto255::element_to_bytes(statement.y2());

    let mut transcript = Transcript::new();
    transcript.append_context(challenge_id);
    let proof = prover
        .prove_with_transcript(&mut rng, &mut transcript)
        .unwrap();
    let proof_bytes = proof.to_bytes().unwrap();

    (y1, y2, proof_bytes)
}

fn derive_scalar_from_password(password: &str, user_id: &str) -> <Ristretto255 as Group>::Scalar {
    use sha2::{Digest, Sha256, Sha512};

    let salt_input = format!("chaum-pedersen-v1.0.0-{}", user_id);
    let salt_hash = Sha256::digest(salt_input.as_bytes());
    let salt = &salt_hash[0..16];

    use argon2::Algorithm;

    let argon2 = argon2::Argon2::new(Algorithm::Argon2id, Default::default(), Default::default());
    let mut output_key_material = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .unwrap();

    let mut hasher = Sha512::new();
    hasher.update(output_key_material);
    hasher.update(b"chaum-pedersen-zkp-scalar-derivation");
    let hash = hasher.finalize();

    use curve25519_dalek::scalar::Scalar as DalekScalar;
    let scalar = DalekScalar::from_bytes_mod_order_wide(&hash.into());

    let scalar_bytes = scalar.to_bytes();
    Ristretto255::scalar_from_bytes(&scalar_bytes).unwrap()
}

#[tokio::test]
async fn batch_verify_multiple_valid_proofs() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let num_users = 10;
    let mut user_ids = Vec::new();
    let mut challenge_ids = Vec::new();
    let mut proofs = Vec::new();

    for i in 0..num_users {
        let user_id = format!("batch_user_{}", i);

        let (y1, y2, _) = generate_proof_for_user(&user_id, b"dummy");

        let reg_req = RegistrationRequest {
            user_id: user_id.clone(),
            y1,
            y2,
            group_name: "Ristretto255".to_string(),
        };
        let reg_resp = client.register(reg_req).await.unwrap();
        assert!(reg_resp.into_inner().success);

        let challenge_req = ChallengeRequest {
            user_id: user_id.clone(),
        };
        let challenge_resp = client.create_challenge(challenge_req).await.unwrap();
        let challenge_id = challenge_resp.into_inner().challenge_id;

        let (_, _, proof_bytes) = generate_proof_for_user(&user_id, &challenge_id);

        user_ids.push(user_id);
        challenge_ids.push(challenge_id);
        proofs.push(proof_bytes);
    }

    let batch_req = BatchVerificationRequest {
        user_ids: user_ids.clone(),
        challenge_ids,
        proofs,
    };

    let batch_resp = client.verify_proof_batch(batch_req).await.unwrap();
    let results = batch_resp.into_inner().results;

    assert_eq!(results.len(), num_users);
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.success,
            "Proof {} should be valid for user {}",
            i, user_ids[i]
        );
        assert!(result.session_token.is_some());
    }
}

#[tokio::test]
async fn batch_verify_mixed_valid_invalid_proofs() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let num_users = 10;
    let mut user_ids = Vec::new();
    let mut challenge_ids = Vec::new();
    let mut proofs = Vec::new();

    for i in 0..num_users {
        let user_id = format!("mixed_user_{}", i);

        let (y1, y2, _) = generate_proof_for_user(&user_id, b"dummy");

        let reg_req = RegistrationRequest {
            user_id: user_id.clone(),
            y1,
            y2,
            group_name: "Ristretto255".to_string(),
        };
        client.register(reg_req).await.unwrap();

        let challenge_req = ChallengeRequest {
            user_id: user_id.clone(),
        };
        let challenge_resp = client.create_challenge(challenge_req).await.unwrap();
        let challenge_id = challenge_resp.into_inner().challenge_id;

        let proof_bytes = if i % 2 == 0 {
            let (_, _, proof) = generate_proof_for_user(&user_id, &challenge_id);
            proof
        } else {
            let (_, _, proof) = generate_proof_for_user(&user_id, b"wrong-challenge");
            proof
        };

        user_ids.push(user_id);
        challenge_ids.push(challenge_id);
        proofs.push(proof_bytes);
    }

    let batch_req = BatchVerificationRequest {
        user_ids: user_ids.clone(),
        challenge_ids,
        proofs,
    };

    let batch_resp = client.verify_proof_batch(batch_req).await.unwrap();
    let results = batch_resp.into_inner().results;

    assert_eq!(results.len(), num_users);
    for (i, result) in results.iter().enumerate() {
        if i % 2 == 0 {
            assert!(result.success, "Even-indexed proof {} should be valid", i);
            assert!(result.session_token.is_some());
        } else {
            assert!(!result.success, "Odd-indexed proof {} should be invalid", i);
            assert!(result.session_token.is_none());
        }
    }
}

#[tokio::test]
async fn batch_verify_empty_batch_error() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let batch_req = BatchVerificationRequest {
        user_ids: vec![],
        challenge_ids: vec![],
        proofs: vec![],
    };

    let result = client.verify_proof_batch(batch_req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn batch_verify_mismatched_array_lengths() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let batch_req = BatchVerificationRequest {
        user_ids: vec!["user1".to_string()],
        challenge_ids: vec![vec![1, 2, 3]],
        proofs: vec![],
    };

    let result = client.verify_proof_batch(batch_req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn batch_verify_exceeds_size_limit() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let user_ids = vec!["user".to_string(); 1001];
    let challenge_ids = vec![vec![1u8; 32]; 1001];
    let proofs = vec![vec![1u8; 100]; 1001];

    let batch_req = BatchVerificationRequest {
        user_ids,
        challenge_ids,
        proofs,
    };

    let result = client.verify_proof_batch(batch_req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn batch_verify_single_proof() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let user_id = "single_batch_user".to_string();
    let (y1, y2, _) = generate_proof_for_user(&user_id, b"dummy");

    let reg_req = RegistrationRequest {
        user_id: user_id.clone(),
        y1,
        y2,
        group_name: "Ristretto255".to_string(),
    };
    client.register(reg_req).await.unwrap();

    let challenge_req = ChallengeRequest {
        user_id: user_id.clone(),
    };
    let challenge_resp = client.create_challenge(challenge_req).await.unwrap();
    let challenge_id = challenge_resp.into_inner().challenge_id;

    let (_, _, proof_bytes) = generate_proof_for_user(&user_id, &challenge_id);

    let batch_req = BatchVerificationRequest {
        user_ids: vec![user_id.clone()],
        challenge_ids: vec![challenge_id],
        proofs: vec![proof_bytes],
    };

    let batch_resp = client.verify_proof_batch(batch_req).await.unwrap();
    let results = batch_resp.into_inner().results;

    assert_eq!(results.len(), 1);
    assert!(results[0].success);
    assert!(results[0].session_token.is_some());
}

#[tokio::test]
async fn batch_register_multiple_users() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let num_users = 10;
    let mut user_ids = Vec::new();
    let mut y1_values = Vec::new();
    let mut y2_values = Vec::new();

    for i in 0..num_users {
        let user_id = format!("batch_reg_user_{}", i);
        let (y1, y2, _) = generate_proof_for_user(&user_id, b"dummy");

        user_ids.push(user_id);
        y1_values.push(y1);
        y2_values.push(y2);
    }

    let batch_req = BatchRegistrationRequest {
        user_ids: user_ids.clone(),
        y1_values,
        y2_values,
        group_name: "Ristretto255".to_string(),
    };

    let batch_resp = client.register_batch(batch_req).await.unwrap();
    let results = batch_resp.into_inner().results;

    assert_eq!(results.len(), num_users);
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.success,
            "Registration {} should succeed for user {}",
            i, user_ids[i]
        );
    }
}

#[tokio::test]
async fn batch_register_duplicate_users() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let user_id = "duplicate_user".to_string();
    let (y1, y2, _) = generate_proof_for_user(&user_id, b"dummy");

    let reg_req = RegistrationRequest {
        user_id: user_id.clone(),
        y1: y1.clone(),
        y2: y2.clone(),
        group_name: "Ristretto255".to_string(),
    };
    client.register(reg_req).await.unwrap();

    let batch_req = BatchRegistrationRequest {
        user_ids: vec![user_id.clone(), user_id.clone()],
        y1_values: vec![y1.clone(), y1],
        y2_values: vec![y2.clone(), y2],
        group_name: "Ristretto255".to_string(),
    };

    let batch_resp = client.register_batch(batch_req).await.unwrap();
    let results = batch_resp.into_inner().results;

    assert_eq!(results.len(), 2);
    assert!(
        !results[0].success,
        "First registration should fail (already exists)"
    );
    assert!(
        !results[1].success,
        "Second registration should fail (already exists)"
    );
}

#[tokio::test]
async fn batch_register_empty_batch() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let batch_req = BatchRegistrationRequest {
        user_ids: vec![],
        y1_values: vec![],
        y2_values: vec![],
        group_name: "Ristretto255".to_string(),
    };

    let result = client.register_batch(batch_req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn batch_register_mismatched_arrays() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let batch_req = BatchRegistrationRequest {
        user_ids: vec!["user1".to_string()],
        y1_values: vec![vec![1u8; 32]],
        y2_values: vec![],
        group_name: "Ristretto255".to_string(),
    };

    let result = client.register_batch(batch_req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn batch_verify_large_batch() {
    let (server_addr, _handle) = start_test_server().await;
    let mut client = AuthServiceClient::connect(server_addr).await.unwrap();

    let num_users = 100;
    let mut user_ids = Vec::new();
    let mut challenge_ids = Vec::new();
    let mut proofs = Vec::new();

    for i in 0..num_users {
        let user_id = format!("large_batch_user_{}", i);
        let (y1, y2, _) = generate_proof_for_user(&user_id, b"dummy");

        let reg_req = RegistrationRequest {
            user_id: user_id.clone(),
            y1,
            y2,
            group_name: "Ristretto255".to_string(),
        };
        client.register(reg_req).await.unwrap();

        let challenge_req = ChallengeRequest {
            user_id: user_id.clone(),
        };
        let challenge_resp = client.create_challenge(challenge_req).await.unwrap();
        let challenge_id = challenge_resp.into_inner().challenge_id;

        let (_, _, proof_bytes) = generate_proof_for_user(&user_id, &challenge_id);

        user_ids.push(user_id);
        challenge_ids.push(challenge_id);
        proofs.push(proof_bytes);
    }

    let batch_req = BatchVerificationRequest {
        user_ids: user_ids.clone(),
        challenge_ids,
        proofs,
    };

    let batch_resp = client.verify_proof_batch(batch_req).await.unwrap();
    let results = batch_resp.into_inner().results;

    assert_eq!(results.len(), num_users);
    let successful = results.iter().filter(|r| r.success).count();
    assert_eq!(successful, num_users);
}
