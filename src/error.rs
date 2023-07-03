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
    #[error("invalid server config (expected {expected}, found {found})")]
    InvalidServerConfig { expected: String, found: String },
    /// Indicates that the configured address and port were not available to listen on.
    #[error("cannot bind to {addr} on any port from {}-{}", port_range.start, port_range.end - 1)]
    CannotBindAddress {
        addr: IpAddr,
        port_range: Range<u16>,
    },
}

/// Defines the types of errors that can occur from the internal web server during the OAuth flow.
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("i/o error")]
    IoError(#[from] io::Error),
    #[error("tokio must be running")]
    AsyncRuntimeRequired(#[from] TryCurrentError),
    #[error("error sending message")]
    SendError(#[from] mpsc::error::SendError<ServerControl>),
    #[error("server startup failed")]
    StartupFailed,
    #[error("server error")]
    ServerError(#[from] JoinError),
    #[error("request error")]
    RequestError(#[from] hyper::Error),
    #[error("encoding error")]
    EncodingError(#[from] FromUtf8Error),
    #[error("no result received")]
    NoResult,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("invalid CSRF token (state parameter)")]
    CsrfMismatch,
    #[error("no result received")]
    NoResult,
}
