#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid group parameters: {0}")]
    InvalidParams(String),

    #[error("Invalid scalar: {0}")]
    InvalidScalar(String),

    #[error("Invalid group element: {0}")]
    InvalidGroupElement(String),
}
