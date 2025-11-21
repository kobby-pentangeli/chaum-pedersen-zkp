use std::time::Instant;

#[cfg(feature = "server")]
use metrics::{counter, histogram};
use rand_core::RngCore;
use tonic::{Request, Response, Status};

use super::config::RateLimiter;
use super::state::{ServerState, UserData};
use crate::proto::auth_service_server::AuthService;
use crate::proto::{
    BatchRegistrationRequest, BatchRegistrationResponse, BatchVerificationRequest,
    BatchVerificationResponse, ChallengeRequest, ChallengeResponse, RegistrationRequest,
    RegistrationResponse, RegistrationResult, VerificationRequest, VerificationResponse,
    VerificationResult,
};
use crate::{
    BatchVerifier, Group, Parameters, Proof, Ristretto255, SecureRng, Statement, Transcript,
    Verifier,
};

/// gRPC service implementation for Chaum-Pedersen authentication.
pub struct AuthServiceImpl<G: Group> {
    state: ServerState<G>,
    rate_limiter: RateLimiter,
}

impl<G: Group> AuthServiceImpl<G> {
    /// Creates a new authentication service with the given state and rate limiter.
    pub fn new(state: ServerState<G>, rate_limiter: RateLimiter) -> Self {
        Self {
            state,
            rate_limiter,
        }
    }

    #[allow(clippy::result_large_err)]
    fn validate_user_id(user_id: &str) -> Result<(), Status> {
        if user_id.is_empty() {
            return Err(Status::invalid_argument("User ID cannot be empty"));
        }

        if user_id.len() > 256 {
            return Err(Status::invalid_argument("User ID too long"));
        }

        if !user_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(Status::invalid_argument(
                "User ID contains invalid characters",
            ));
        }

        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_group_name(group_name: &str) -> Result<(), Status> {
        match group_name {
            "Ristretto255" => Ok(()),
            _ => Err(Status::unimplemented(format!(
                "Group '{group_name}' is not supported. Currently only 'Ristretto255' is implemented."
            ))),
        }
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl<Ristretto255> {
    async fn register(
        &self,
        request: Request<RegistrationRequest>,
    ) -> Result<Response<RegistrationResponse>, Status> {
        let start = Instant::now();
        counter!("auth.register.requests").increment(1);

        self.rate_limiter.check_rate_limit().await?;

        let req = request.into_inner();

        Self::validate_user_id(&req.user_id)?;
        Self::validate_group_name(&req.group_name)?;

        if req.y1.is_empty() || req.y2.is_empty() {
            return Err(Status::invalid_argument("Empty y1 or y2 values"));
        }

        if req.y1.len() > 4096 || req.y2.len() > 4096 {
            return Err(Status::invalid_argument("y1 or y2 values too large"));
        }

        let y1 = Ristretto255::element_from_bytes(&req.y1)
            .map_err(|e| Status::invalid_argument(format!("Invalid y1: {e}")))?;

        let y2 = Ristretto255::element_from_bytes(&req.y2)
            .map_err(|e| Status::invalid_argument(format!("Invalid y2: {e}")))?;

        let statement = Statement::new(y1, y2);
        statement
            .validate()
            .map_err(|e| Status::invalid_argument(format!("Invalid statement: {e}")))?;

        if Ristretto255::is_identity(statement.y1()) || Ristretto255::is_identity(statement.y2()) {
            return Err(Status::invalid_argument(
                "Statement contains identity elements",
            ));
        }

        let user_data = UserData {
            user_id: req.user_id.clone(),
            statement,
            group_name: req.group_name,
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| unreachable!("System time is after UNIX_EPOCH"))
                .as_secs(),
        };

        let result = self
            .state
            .register_user(user_data)
            .await
            .map_err(|e| Status::already_exists(format!("Registration failed: {e}")));

        histogram!("auth.register.duration").record(start.elapsed().as_secs_f64());

        if result.is_ok() {
            counter!("auth.register.success").increment(1);
        } else {
            counter!("auth.register.failure").increment(1);
        }

        result?;

        Ok(Response::new(RegistrationResponse {
            success: true,
            message: format!("User '{}' registered successfully", req.user_id),
        }))
    }

    async fn register_batch(
        &self,
        request: Request<BatchRegistrationRequest>,
    ) -> Result<Response<BatchRegistrationResponse>, Status> {
        let start = Instant::now();
        counter!("auth.register_batch.requests").increment(1);

        self.rate_limiter.check_rate_limit().await?;

        let req = request.into_inner();

        if req.user_ids.is_empty() {
            return Err(Status::invalid_argument("Empty batch"));
        }

        if req.user_ids.len() != req.y1_values.len() || req.user_ids.len() != req.y2_values.len() {
            return Err(Status::invalid_argument(
                "Mismatched array lengths in batch request",
            ));
        }

        if req.user_ids.len() > 1000 {
            return Err(Status::invalid_argument(
                "Batch size exceeds maximum limit of 1000",
            ));
        }

        Self::validate_group_name(&req.group_name)?;

        counter!("auth.register_batch.users_count").increment(req.user_ids.len() as u64);

        let batch_size = req.user_ids.len();
        let mut results = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let user_id = &req.user_ids[i];
            let y1_bytes = &req.y1_values[i];
            let y2_bytes = &req.y2_values[i];

            let registration_result: Result<(), Status> = (|| {
                Self::validate_user_id(user_id)?;

                if y1_bytes.is_empty() || y2_bytes.is_empty() {
                    return Err(Status::invalid_argument(format!(
                        "Empty y1 or y2 values for user {}",
                        i
                    )));
                }

                if y1_bytes.len() > 4096 || y2_bytes.len() > 4096 {
                    return Err(Status::invalid_argument(format!(
                        "y1 or y2 values too large for user {}",
                        i
                    )));
                }

                Ok(())
            })();

            if let Err(e) = registration_result {
                results.push(RegistrationResult {
                    success: false,
                    message: e.message().to_string(),
                });
                counter!("auth.register_batch.individual_failure").increment(1);
                continue;
            }

            let y1 = match Ristretto255::element_from_bytes(y1_bytes) {
                Ok(v) => v,
                Err(e) => {
                    results.push(RegistrationResult {
                        success: false,
                        message: format!("Invalid y1: {e}"),
                    });
                    counter!("auth.register_batch.individual_failure").increment(1);
                    continue;
                }
            };

            let y2 = match Ristretto255::element_from_bytes(y2_bytes) {
                Ok(v) => v,
                Err(e) => {
                    results.push(RegistrationResult {
                        success: false,
                        message: format!("Invalid y2: {e}"),
                    });
                    counter!("auth.register_batch.individual_failure").increment(1);
                    continue;
                }
            };

            let statement = Statement::new(y1, y2);
            if let Err(e) = statement.validate() {
                results.push(RegistrationResult {
                    success: false,
                    message: format!("Invalid statement: {e}"),
                });
                counter!("auth.register_batch.individual_failure").increment(1);
                continue;
            }

            if Ristretto255::is_identity(statement.y1())
                || Ristretto255::is_identity(statement.y2())
            {
                results.push(RegistrationResult {
                    success: false,
                    message: "Statement contains identity elements".to_string(),
                });
                counter!("auth.register_batch.individual_failure").increment(1);
                continue;
            }

            let user_data = UserData {
                user_id: user_id.clone(),
                statement,
                group_name: req.group_name.clone(),
                registered_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| unreachable!("System time is after UNIX_EPOCH"))
                    .as_secs(),
            };

            match self.state.register_user(user_data).await {
                Ok(_) => {
                    results.push(RegistrationResult {
                        success: true,
                        message: format!("User '{}' registered successfully", user_id),
                    });
                    counter!("auth.register_batch.individual_success").increment(1);
                }
                Err(e) => {
                    results.push(RegistrationResult {
                        success: false,
                        message: format!("Registration failed: {e}"),
                    });
                    counter!("auth.register_batch.individual_failure").increment(1);
                }
            }
        }

        histogram!("auth.register_batch.duration").record(start.elapsed().as_secs_f64());
        counter!("auth.register_batch.success").increment(1);

        Ok(Response::new(BatchRegistrationResponse { results }))
    }

    async fn create_challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let start = Instant::now();
        counter!("auth.challenge.requests").increment(1);

        self.rate_limiter.check_rate_limit().await?;

        let req = request.into_inner();

        Self::validate_user_id(&req.user_id)?;

        let user = self
            .state
            .get_user(&req.user_id)
            .await
            .ok_or_else(|| Status::not_found(format!("User '{}' not found", req.user_id)))?;

        let mut rng = SecureRng::new();
        let mut challenge_id = vec![0u8; 32];
        rng.fill_bytes(&mut challenge_id);

        let result = self
            .state
            .create_challenge(&user.user_id, challenge_id.clone())
            .await
            .map_err(|e| Status::resource_exhausted(format!("Challenge creation failed: {e}")));

        histogram!("auth.challenge.duration").record(start.elapsed().as_secs_f64());

        if result.is_ok() {
            counter!("auth.challenge.success").increment(1);
        } else {
            counter!("auth.challenge.failure").increment(1);
        }

        let expires_at = result?;

        let expires_at_i64 = i64::try_from(expires_at).unwrap_or(i64::MAX);

        Ok(Response::new(ChallengeResponse {
            challenge_id,
            expires_at: expires_at_i64,
        }))
    }

    async fn verify_proof(
        &self,
        request: Request<VerificationRequest>,
    ) -> Result<Response<VerificationResponse>, Status> {
        let start = Instant::now();
        counter!("auth.verify.requests").increment(1);

        self.rate_limiter.check_rate_limit().await?;

        let req = request.into_inner();

        Self::validate_user_id(&req.user_id)?;

        if req.challenge_id.is_empty() {
            return Err(Status::invalid_argument("Empty challenge ID"));
        }

        if req.challenge_id.len() > 64 {
            return Err(Status::invalid_argument("Challenge ID too long"));
        }

        if req.proof.is_empty() {
            return Err(Status::invalid_argument("Empty proof"));
        }

        if req.proof.len() > 8192 {
            return Err(Status::invalid_argument("Proof too large"));
        }

        let challenge_data = self
            .state
            .consume_challenge(&req.challenge_id)
            .await
            .map_err(|_| Status::permission_denied("Authentication failed"))?;

        if challenge_data.user_id != req.user_id {
            return Err(Status::permission_denied("Authentication failed"));
        }

        let user = self
            .state
            .get_user(&req.user_id)
            .await
            .ok_or_else(|| Status::permission_denied("Authentication failed"))?;

        let proof = Proof::<Ristretto255>::from_bytes(&req.proof)
            .map_err(|e| Status::invalid_argument(format!("Invalid proof: {e}")))?;

        let params = Parameters::<Ristretto255>::new();
        let verifier = Verifier::new(params, user.statement);

        let mut transcript = Transcript::new();
        transcript.append_context(&req.challenge_id);

        verifier
            .verify_with_transcript(&proof, &mut transcript)
            .map_err(|e| Status::permission_denied(format!("Verification failed: {e}")))?;

        let mut rng = SecureRng::new();
        let mut session_token = vec![0u8; 32];
        rng.fill_bytes(&mut session_token);
        let session_token_hex = hex::encode(&session_token);

        // Store the session
        let result = self
            .state
            .create_session(session_token_hex.clone(), req.user_id.clone())
            .await
            .map_err(|e| Status::internal(format!("Failed to create session: {e}")));

        histogram!("auth.verify.duration").record(start.elapsed().as_secs_f64());

        if result.is_ok() {
            counter!("auth.verify.success").increment(1);
        } else {
            counter!("auth.verify.failure").increment(1);
        }

        result?;

        Ok(Response::new(VerificationResponse {
            success: true,
            message: format!("User '{}' authenticated successfully", req.user_id),
            session_token: Some(session_token_hex),
        }))
    }

    async fn verify_proof_batch(
        &self,
        request: Request<BatchVerificationRequest>,
    ) -> Result<Response<BatchVerificationResponse>, Status> {
        let start = Instant::now();
        counter!("auth.verify_batch.requests").increment(1);

        self.rate_limiter.check_rate_limit().await?;

        let req = request.into_inner();

        if req.user_ids.is_empty() {
            return Err(Status::invalid_argument("Empty batch"));
        }

        if req.user_ids.len() != req.challenge_ids.len() || req.user_ids.len() != req.proofs.len() {
            return Err(Status::invalid_argument(
                "Mismatched array lengths in batch request",
            ));
        }

        if req.user_ids.len() > 1000 {
            return Err(Status::invalid_argument(
                "Batch size exceeds maximum limit of 1000",
            ));
        }

        counter!("auth.verify_batch.proofs_count").increment(req.user_ids.len() as u64);

        let batch_size = req.user_ids.len();
        let mut batch_verifier = BatchVerifier::<Ristretto255>::with_capacity(batch_size);
        let mut user_contexts = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let user_id = &req.user_ids[i];
            let challenge_id = &req.challenge_ids[i];
            let proof_bytes = &req.proofs[i];

            let validation_result: Result<(), Status> = (|| {
                Self::validate_user_id(user_id)?;

                if challenge_id.is_empty() {
                    return Err(Status::invalid_argument(format!(
                        "Empty challenge ID for proof {}",
                        i
                    )));
                }

                if challenge_id.len() > 64 {
                    return Err(Status::invalid_argument(format!(
                        "Challenge ID too long for proof {}",
                        i
                    )));
                }

                if proof_bytes.is_empty() {
                    return Err(Status::invalid_argument(format!("Empty proof {}", i)));
                }

                if proof_bytes.len() > 8192 {
                    return Err(Status::invalid_argument(format!("Proof {} too large", i)));
                }

                Ok(())
            })();

            if let Err(e) = validation_result {
                user_contexts.push(Err(e));
                continue;
            }

            let challenge_result = self.state.consume_challenge(challenge_id).await;

            let challenge_data = match challenge_result {
                Ok(data) => data,
                Err(_) => {
                    user_contexts.push(Err(Status::permission_denied("Authentication failed")));
                    continue;
                }
            };

            if challenge_data.user_id != *user_id {
                user_contexts.push(Err(Status::permission_denied("Authentication failed")));
                continue;
            }

            let user = match self.state.get_user(user_id).await {
                Some(u) => u,
                None => {
                    user_contexts.push(Err(Status::permission_denied("Authentication failed")));
                    continue;
                }
            };

            let proof = match Proof::<Ristretto255>::from_bytes(proof_bytes) {
                Ok(p) => p,
                Err(e) => {
                    user_contexts
                        .push(Err(Status::invalid_argument(format!("Invalid proof: {e}"))));
                    continue;
                }
            };

            let params = Parameters::<Ristretto255>::new();

            match batch_verifier.add_with_context(
                params,
                user.statement,
                proof,
                Some(challenge_id.clone()),
            ) {
                Ok(_) => {
                    user_contexts.push(Ok(user_id.clone()));
                }
                Err(e) => {
                    user_contexts.push(Err(Status::invalid_argument(format!(
                        "Failed to add proof to batch: {e}"
                    ))));
                }
            }
        }

        let mut rng = SecureRng::new();
        let batch_results = if batch_verifier.is_empty() {
            vec![]
        } else {
            match batch_verifier.verify(&mut rng) {
                Ok(results) => results,
                Err(e) => {
                    counter!("auth.verify_batch.failure").increment(1);
                    return Err(Status::internal(format!("Batch verification failed: {e}")));
                }
            }
        };

        let mut verification_results = Vec::with_capacity(batch_size);
        let mut batch_index = 0;

        for context_result in user_contexts {
            match context_result {
                Ok(user_id) => {
                    if batch_index < batch_results.len() {
                        let verify_result = &batch_results[batch_index];
                        batch_index += 1;

                        if verify_result.is_ok() {
                            let mut session_token_bytes = vec![0u8; 32];
                            rng.fill_bytes(&mut session_token_bytes);
                            let session_token_hex = hex::encode(&session_token_bytes);

                            match self
                                .state
                                .create_session(session_token_hex.clone(), user_id.clone())
                                .await
                            {
                                Ok(_) => {
                                    verification_results.push(VerificationResult {
                                        success: true,
                                        message: format!(
                                            "User '{}' authenticated successfully",
                                            user_id
                                        ),
                                        session_token: Some(session_token_hex),
                                    });
                                    counter!("auth.verify_batch.individual_success").increment(1);
                                }
                                Err(e) => {
                                    verification_results.push(VerificationResult {
                                        success: false,
                                        message: format!("Failed to create session: {e}"),
                                        session_token: None,
                                    });
                                    counter!("auth.verify_batch.individual_failure").increment(1);
                                }
                            }
                        } else {
                            verification_results.push(VerificationResult {
                                success: false,
                                message: "Authentication failed".to_string(),
                                session_token: None,
                            });
                            counter!("auth.verify_batch.individual_failure").increment(1);
                        }
                    } else {
                        verification_results.push(VerificationResult {
                            success: false,
                            message: "Internal verification error".to_string(),
                            session_token: None,
                        });
                        counter!("auth.verify_batch.individual_failure").increment(1);
                    }
                }
                Err(status) => {
                    verification_results.push(VerificationResult {
                        success: false,
                        message: status.message().to_string(),
                        session_token: None,
                    });
                    counter!("auth.verify_batch.individual_failure").increment(1);
                }
            }
        }

        histogram!("auth.verify_batch.duration").record(start.elapsed().as_secs_f64());
        counter!("auth.verify_batch.success").increment(1);

        Ok(Response::new(BatchVerificationResponse {
            results: verification_results,
        }))
    }
}
