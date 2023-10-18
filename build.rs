fn main() {
    tonic_build::configure()
        .build_server(true)
        .out_dir("build/")
        .compile(&["proto/chaum_pedersen_auth.proto"], &["proto/"])
        .unwrap();
}
