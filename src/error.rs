use std::io;
use std::net::IpAddr;
use std::ops::Range;
use std::string::FromUtf8Error;

use crate::server::ServerControl;
use thiserror::Error;
use tokio::runtime::TryCurrentError;
use tokio::sync::mpsc;
use tokio::task::JoinError;

/// Defines the types of errors that can occur during helper configuration.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Indicates that the web server parameters were not correct.
    #[error("Invalid server config (expected {expected}, found {found})")]
    InvalidServerConfig { expected: String, found: String },
    /// Indicates that the configured address and port were not available to listen on.
    #[error("Cannot bind to {addr} on any port from {}-{}", port_range.start, port_range.end - 1)]
    CannotBindAddress {
        addr: IpAddr,
        port_range: Range<u16>,
    },
}

/// Defines the types of errors that can occur from the internal web server during the OAuth flow.
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("I/O error")]
    IoError(#[from] io::Error),
    /// Indicates that a Tokio runtime could not be found
    #[error("Tokio must be running")]
    AsyncRuntimeRequired(#[from] TryCurrentError),
    /// Indicates an error sending a signal to the internal server
    #[error("Error signaling server")]
    InternalCommError(#[from] mpsc::error::SendError<ServerControl>),
    /// Indicates a problem running the server
    #[error("Internal server error")]
    InternalServerError(#[from] JoinError),
    #[error("Request error")]
    RequestError(#[from] hyper::Error),
    #[error("Encoding error")]
    EncodingError(#[from] FromUtf8Error),
    /// No authorization code was received
    #[error("No authorization code received")]
    NoResult,
}

/// Defines the types of errors that can occur during the authorization flow.
#[derive(Error, Debug)]
pub enum AuthError {
    /// Invalid CSRF token (state parameter). Indicates a possible replay attack.
    #[error("Invalid CSRF token (state parameter)")]
    CsrfMismatch,
    /// No authorization code or PKCE verifier present. Might indicate that `validate` was invoked
    /// without a successful call to `authorize`.
    #[error("No authorization code or PKCE verifier present")]
    InvalidAuthState,
}
