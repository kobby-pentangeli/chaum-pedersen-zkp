use rand_core::RngCore;
use tonic::{Request, Response, Status};

use super::state::{ServerState, UserData};
use crate::proto::auth_service_server::AuthService;
use crate::proto::{
    ChallengeRequest, ChallengeResponse, RegistrationRequest, RegistrationResponse,
    VerificationRequest, VerificationResponse,
};
use crate::{Group, Parameters, Proof, Ristretto255, SecureRng, Statement, Transcript, Verifier};

/// gRPC service implementation for Chaum-Pedersen authentication.
pub struct AuthServiceImpl<G: Group> {
    state: ServerState<G>,
}

impl<G: Group> AuthServiceImpl<G> {
    /// Creates a new authentication service with the given state.
    pub fn new(state: ServerState<G>) -> Self {
        Self { state }
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

        self.state
            .register_user(user_data)
            .await
            .map_err(|e| Status::already_exists(format!("Registration failed: {e}")))?;

        Ok(Response::new(RegistrationResponse {
            success: true,
            message: format!("User '{}' registered successfully", req.user_id),
        }))
    }

    async fn create_challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
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

        let expires_at = self
            .state
            .create_challenge(&user.user_id, challenge_id.clone())
            .await
            .map_err(|e| Status::resource_exhausted(format!("Challenge creation failed: {e}")))?;

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
            .map_err(|e| Status::invalid_argument(format!("Invalid challenge: {e}")))?;

        if challenge_data.user_id != req.user_id {
            return Err(Status::permission_denied("Challenge/user mismatch"));
        }

        let user = self
            .state
            .get_user(&req.user_id)
            .await
            .ok_or_else(|| Status::not_found(format!("User '{}' not found", req.user_id)))?;

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

        Ok(Response::new(VerificationResponse {
            success: true,
            message: format!("User '{}' authenticated successfully", req.user_id),
            session_token: Some(session_token_hex),
        }))
    }
}
