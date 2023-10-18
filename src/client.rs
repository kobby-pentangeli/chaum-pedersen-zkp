use num_bigint::BigUint;
use std::io;

mod chaum_pedersen_auth {
    include!("./chaum_pedersen_auth.rs");
}

use chaum_pedersen_auth::{
    auth_client::AuthClient, AuthChallengeRequest, AuthVerificationRequest, RegistrationRequest,
};
use chaum_pedersen_zkp::{
    generate_1024bit_group_with_160bit_constants, generate_random_biguint_below, Protocol,
};

#[tokio::main]
async fn main() {
    let mut buf = String::new();

    let Protocol { p, q, g, h } = generate_1024bit_group_with_160bit_constants();
    let protocol = Protocol {
        p: p.clone(),
        q: q.clone(),
        g: g.clone(),
        h: h.clone(),
    };

    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("Could not connect to server!");
    println!("✅ Connection established!");

    println!("Please state username:");
    io::stdin()
        .read_line(&mut buf)
        .expect("Error reading username");
    let username = buf.trim().to_string();
    buf.clear();

    println!("Please provide password:");
    io::stdin()
        .read_line(&mut buf)
        .expect("Couldn't read password");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let (y1, y2) = protocol.compute_parameters(&password);
    let registration_request = RegistrationRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _registration_response = client
        .register(registration_request)
        .await
        .expect("Couldn't register user");
    println!("✅ Registration was successful");

    let k = generate_random_biguint_below(&q);
    let (r1, r2) = protocol.compute_parameters(&k);
    let challenge_request = AuthChallengeRequest {
        user: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };
    let challenge_response = client
        .create_auth_challenge(challenge_request)
        .await
        .expect("Failed to create Auth Challenge")
        .into_inner();

    let auth_id = challenge_response.auth_id;
    let c = BigUint::from_bytes_be(&challenge_response.c);
    let s = protocol.solve_challenge(&k, &c, &password);
    let verification_request = AuthVerificationRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    let verification_response = client
        .verify_auth(verification_request)
        .await
        .expect("Couldn't verify auth proof")
        .into_inner();

    println!(
        "✅ Successful login! session_id: {}",
        verification_response.session_id
    );
}
