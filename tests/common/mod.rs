//! Common test utilities shared across integration tests.

/// Initialize test tracing (call once at the beginning of tests).
///
/// This sets up tracing for tests with INFO level output to the test writer.
/// Only logs from the test crate are shown, filtering out HTTP/2 and tower noise.
/// Subsequent calls are safe and will be ignored.
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::new("batch_verification_tests=info");

    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(filter)
        .try_init();
}
