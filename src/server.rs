use chaum_pedersen_zkp::{
    generate_1024bit_group_with_160bit_constants, generate_random_biguint_below,
    generate_random_string, Protocol,
};
use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use tonic::{transport::Server, Code, Request, Response, Status};

mod chaum_pedersen_auth {
    include!("../build/chaum_pedersen_auth.rs");
}

use chaum_pedersen_auth::{
    auth_server::{Auth, AuthServer},
    AuthChallengeRequest, AuthChallengeResponse, AuthVerificationRequest, AuthVerificationResponse,
    RegistrationRequest, RegistrationResponse,
};

#[derive(Debug, Default)]
pub struct User {
    pub info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    pub username: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub r1: BigUint,
    pub r2: BigUint,
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for User {
    async fn register(
        &self,
        request: Request<RegistrationRequest>,
    ) -> Result<Response<RegistrationResponse>, Status> {
        let request = request.into_inner();

        let username = request.user;
        println!("Registering user: {:?}", username);

        let user_info = UserInfo {
            username: username.clone(),
            y1: BigUint::from_bytes_be(&request.y1),
            y2: BigUint::from_bytes_be(&request.y2),
            ..Default::default()
        };

        let user_info_map = &mut self.info.lock().unwrap();
        user_info_map.insert(username.clone(), user_info);

        println!("{:?} successfully registered!✅", username);
        Ok(Response::new(RegistrationResponse {}))
    }

    async fn create_auth_challenge(
        &self,
        request: Request<AuthChallengeRequest>,
    ) -> Result<Response<AuthChallengeResponse>, Status> {
        let request = request.into_inner();

        let username = request.user;
        println!("Creating a challenge for: {:?}", username);

        let user_info_map = &mut self.info.lock().unwrap();

        if let Some(user_info) = user_info_map.get_mut(&username) {
            let Protocol {
                p: _,
                q,
                g: _,
                h: _,
            } = generate_1024bit_group_with_160bit_constants();
            let c = generate_random_biguint_below(&q);
            let auth_id = generate_random_string(12);

            user_info.c = c.clone();
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let user_auth_id = &mut self.auth_id.lock().unwrap();
            user_auth_id.insert(auth_id.clone(), username.clone());

            println!("Challenge for {:?} successfully created!✅", username);

            Ok(Response::new(AuthChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("User: {} not found in database", username),
            ))
        }
    }

    async fn verify_auth(
        &self,
        request: Request<AuthVerificationRequest>,
    ) -> Result<Response<AuthVerificationResponse>, Status> {
        let request = request.into_inner();

        let auth_id = request.auth_id;
        println!("Verifying solution (proof) generated by: {:?}", auth_id);

        let user_auth_id_map = &mut self.auth_id.lock().unwrap();

        if let Some(username) = user_auth_id_map.get(&auth_id) {
            let user_info_map = &mut self.info.lock().unwrap();
            let user_info = user_info_map.get_mut(username).expect("User not found!");

            user_info.s = BigUint::from_bytes_be(&request.s);

            let Protocol { p, q, g, h } = generate_1024bit_group_with_160bit_constants();
            let protocol = Protocol { p, q, g, h };

            let verified = protocol.verify_proof(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &user_info.s,
            );

            if verified {
                let session_id = generate_random_string(12);
                println!("Proof verified and user: {:?} authenticated!✅", username);
                Ok(Response::new(AuthVerificationResponse { session_id }))
            } else {
                println!("Proof rejected and user: {:?} denied access!❌", username);
                Err(Status::new(
                    Code::PermissionDenied,
                    format!("AuthID: {} provided wrong solution to challenge!", auth_id),
                ))
            }
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("AuthID: {} not found in database!", auth_id),
            ))
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();

    println!("✅ Server running at {}", addr);

    let user = User::default();

    Server::builder()
        .add_service(AuthServer::new(user))
        .serve(addr.parse().expect("Couldn't parse socket address!"))
        .await
        .unwrap();
}
