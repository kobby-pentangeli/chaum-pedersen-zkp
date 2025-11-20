#![cfg(all(feature = "server", feature = "grpc"))]

use chaum_pedersen::proto::auth_service_client::AuthServiceClient;
use chaum_pedersen::proto::auth_service_server::AuthServiceServer;
use chaum_pedersen::proto::{ChallengeRequest, RegistrationRequest, VerificationRequest};
use chaum_pedersen::verifier::config::RateLimiter;
use chaum_pedersen::verifier::service::AuthServiceImpl;
use chaum_pedersen::verifier::state::ServerState;
use chaum_pedersen::{
    Group, Parameters, Proof, Prover, Ristretto255, SecureRng, Statement, Transcript, Witness,
};
use tonic::Request;
use tonic::transport::Server;

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let state = ServerState::<Ristretto255>::new();
    let rate_limiter = RateLimiter::new(1000, 100);
    let service = AuthServiceImpl::new(state, rate_limiter);

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (format!("http://{}", local_addr), handle)
}

#[tokio::test]
async fn full_authentication_flow() {
    let (server_url, _handle) = start_test_server().await;

    let mut client = AuthServiceClient::connect(server_url.clone())
        .await
        .expect("Failed to connect to server");

    let params = Parameters::<Ristretto255>::new();
    let mut rng = SecureRng::new();
    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
    let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

    let register_request = Request::new(RegistrationRequest {
        user_id: "alice".to_string(),
        y1: y1_bytes.to_vec(),
        y2: y2_bytes.to_vec(),
        group_name: "Ristretto255".to_string(),
    });

    let register_response = client
        .register(register_request)
        .await
        .expect("Registration should succeed");

    assert!(
        register_response.into_inner().success,
        "Registration should be successful"
    );

    let challenge_request = Request::new(ChallengeRequest {
        user_id: "alice".to_string(),
    });

    let challenge_response = client
        .create_challenge(challenge_request)
        .await
        .expect("Challenge creation should succeed");

    let challenge_response = challenge_response.into_inner();
    let challenge_id = challenge_response.challenge_id;

    let mut transcript = Transcript::new();
    transcript.append_context(&challenge_id);

    let proof = Prover::new(params, witness)
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let proof_bytes = Proof::to_bytes(&proof).expect("Serialization should succeed");

    let verify_request = Request::new(VerificationRequest {
        user_id: "alice".to_string(),
        challenge_id,
        proof: proof_bytes,
    });

    let verify_response = client
        .verify_proof(verify_request)
        .await
        .expect("Verification should succeed");

    let verify_response = verify_response.into_inner();
    assert!(verify_response.success, "Verification should be successful");
    assert!(
        verify_response.session_token.is_some(),
        "Session token should be returned"
    );
}

#[tokio::test]
async fn registration_prevents_duplicates() {
    let (server_url, _handle) = start_test_server().await;

    let mut client = AuthServiceClient::connect(server_url)
        .await
        .expect("Failed to connect to server");

    let params = Parameters::<Ristretto255>::new();
    let mut rng = SecureRng::new();
    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
    let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

    let register_request1 = Request::new(RegistrationRequest {
        user_id: "bob".to_string(),
        y1: y1_bytes.to_vec(),
        y2: y2_bytes.to_vec(),
        group_name: "Ristretto255".to_string(),
    });

    client
        .register(register_request1)
        .await
        .expect("First registration should succeed");

    let register_request2 = Request::new(RegistrationRequest {
        user_id: "bob".to_string(),
        y1: y1_bytes.to_vec(),
        y2: y2_bytes.to_vec(),
        group_name: "Ristretto255".to_string(),
    });

    let result = client.register(register_request2).await;

    assert!(result.is_err(), "Duplicate registration should fail");
}

#[tokio::test]
async fn challenge_single_use() {
    let (server_url, _handle) = start_test_server().await;

    let mut client = AuthServiceClient::connect(server_url)
        .await
        .expect("Failed to connect to server");

    let params = Parameters::<Ristretto255>::new();
    let mut rng = SecureRng::new();
    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
    let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

    let register_request = Request::new(RegistrationRequest {
        user_id: "charlie".to_string(),
        y1: y1_bytes.to_vec(),
        y2: y2_bytes.to_vec(),
        group_name: "Ristretto255".to_string(),
    });

    client.register(register_request).await.unwrap();

    let challenge_request = Request::new(ChallengeRequest {
        user_id: "charlie".to_string(),
    });

    let challenge_response = client.create_challenge(challenge_request).await.unwrap();
    let challenge_id = challenge_response.into_inner().challenge_id;

    let mut transcript = Transcript::new();
    transcript.append_context(&challenge_id);

    let proof = Prover::new(params, witness.clone())
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let proof_bytes = Proof::to_bytes(&proof).expect("Serialization should succeed");

    let verify_request1 = Request::new(VerificationRequest {
        user_id: "charlie".to_string(),
        challenge_id: challenge_id.clone(),
        proof: proof_bytes.clone(),
    });

    client.verify_proof(verify_request1).await.unwrap();

    let verify_request2 = Request::new(VerificationRequest {
        user_id: "charlie".to_string(),
        challenge_id,
        proof: proof_bytes,
    });

    let result = client.verify_proof(verify_request2).await;

    assert!(
        result.is_err(),
        "Challenge should be single-use and fail on second attempt"
    );
}

#[tokio::test]
async fn wrong_password_fails_verification() {
    let (server_url, _handle) = start_test_server().await;

    let mut client = AuthServiceClient::connect(server_url)
        .await
        .expect("Failed to connect to server");

    let params = Parameters::<Ristretto255>::new();
    let mut rng = SecureRng::new();
    let x_correct = Ristretto255::random_scalar(&mut rng);
    let witness_correct = Witness::new(x_correct);
    let statement = Statement::from_witness(&params, &witness_correct);

    let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
    let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

    let register_request = Request::new(RegistrationRequest {
        user_id: "dave".to_string(),
        y1: y1_bytes.to_vec(),
        y2: y2_bytes.to_vec(),
        group_name: "Ristretto255".to_string(),
    });

    client.register(register_request).await.unwrap();

    let challenge_request = Request::new(ChallengeRequest {
        user_id: "dave".to_string(),
    });

    let challenge_response = client.create_challenge(challenge_request).await.unwrap();
    let challenge_id = challenge_response.into_inner().challenge_id;

    let x_wrong = Ristretto255::random_scalar(&mut rng);
    let witness_wrong = Witness::new(x_wrong);

    let mut transcript = Transcript::new();
    transcript.append_context(&challenge_id);

    let proof = Prover::new(params, witness_wrong)
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let proof_bytes = Proof::to_bytes(&proof).expect("Serialization should succeed");

    let verify_request = Request::new(VerificationRequest {
        user_id: "dave".to_string(),
        challenge_id,
        proof: proof_bytes,
    });

    let result = client.verify_proof(verify_request).await;

    assert!(
        result.is_err() || !result.unwrap().into_inner().success,
        "Wrong password should fail verification"
    );
}

#[tokio::test]
async fn max_challenges_per_user() {
    let (server_url, _handle) = start_test_server().await;

    let mut client = AuthServiceClient::connect(server_url)
        .await
        .expect("Failed to connect to server");

    let params = Parameters::<Ristretto255>::new();
    let mut rng = SecureRng::new();
    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
    let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

    let register_request = Request::new(RegistrationRequest {
        user_id: "eve".to_string(),
        y1: y1_bytes.to_vec(),
        y2: y2_bytes.to_vec(),
        group_name: "Ristretto255".to_string(),
    });

    client.register(register_request).await.unwrap();

    for i in 0..3 {
        let challenge_request = Request::new(ChallengeRequest {
            user_id: "eve".to_string(),
        });

        let result = client.create_challenge(challenge_request).await;
        assert!(
            result.is_ok(),
            "Challenge {} should succeed (max 3 allowed)",
            i + 1
        );
    }

    let challenge_request = Request::new(ChallengeRequest {
        user_id: "eve".to_string(),
    });

    let result = client.create_challenge(challenge_request).await;

    assert!(
        result.is_err(),
        "Fourth challenge should fail (max 3 per user)"
    );
}
