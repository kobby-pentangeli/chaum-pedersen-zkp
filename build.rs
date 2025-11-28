fn main() {
    #[cfg(feature = "grpc")]
    {
        tonic_build::configure()
            .build_server(true)
            .out_dir("src/")
            .build_client(true)
            .emit_rerun_if_changed(false)
            .compile_protos(&["proto/auth.proto"], &["proto"])
            .unwrap();
    }
}
