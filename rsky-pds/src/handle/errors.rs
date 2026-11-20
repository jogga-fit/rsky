use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorKind {
    #[error("Invalid handle")]
    InvalidHandle,
    #[error("Handle not available")]
    HandleNotAvailable,
    #[error("Unsupported domain")]
    UnsupportedDomain,
    #[error("Internal error")]
    InternalError,
}

#[derive(Error, Debug)]
#[error("{kind}: {message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: &str) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }
}

impl From<rsky_syntax::handle::service::ServiceHandleError> for Error {
    fn from(e: rsky_syntax::handle::service::ServiceHandleError) -> Self {
        use rsky_syntax::handle::service::ServiceHandleError::Reserved;
        let kind = match e {
            Reserved => ErrorKind::HandleNotAvailable,
            _ => ErrorKind::InvalidHandle,
        };
        Self::new(kind, &e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
