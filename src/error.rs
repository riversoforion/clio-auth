use poem::error::ResponseError;
use poem::http::StatusCode;
use std::io;
use std::net::IpAddr;
use std::ops::Range;

use thiserror::Error;
use tokio::runtime::TryCurrentError;
use tokio::sync::mpsc;
use tokio::task::JoinError;

use crate::server::ServerControl;

/// Errors that can occur during helper configuration.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Web server parameters were not correct.
    #[error("Invalid server config (expected {expected}, found {found})")]
    InvalidServerConfig { expected: String, found: String },
    /// The configured address and port were not available to listen on.
    #[error("Cannot bind to {addr} on any port from {}-{}", port_range.start, port_range.end - 1)]
    CannotBindAddress {
        addr: IpAddr,
        port_range: Range<u16>,
    },
}

/// Errors that can occur from the internal web server during the OAuth flow.
#[derive(Error, Debug)]
pub enum ServerError {
    /// The Tokio runtime could not be found
    #[error("Tokio must be running")]
    AsyncRuntimeRequired(#[from] TryCurrentError),
    #[error("")]
    InternalRuntimeError(#[from] JoinError),
    /// Error sending a signal to the internal server
    #[error("Error signaling server")]
    InternalCommError(#[from] mpsc::error::SendError<ServerControl>),
    /// Problem occurred running the server
    #[error("Internal server error")]
    InternalServerError(#[from] io::Error),
    /// No authorization code was received
    #[error("No authorization code received")]
    NoResult,
}

impl ResponseError for ServerError {
    fn status(&self) -> StatusCode {
        use ServerError::*;
        match self {
            NoResult => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Errors that can occur during the authorization flow.
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

#[cfg(test)]
mod tests {
    mod config_error {
        use crate::ConfigError;

        #[test]
        fn invalid_server_config() {
            let error = ConfigError::InvalidServerConfig {
                expected: "blah".to_owned(),
                found: "foobar".to_owned(),
            };
            assert!(
                format!("{error}").contains("Invalid server config (expected blah, found foobar)")
            );
        }

        #[test]
        fn cannot_bind_address() {
            let error = ConfigError::CannotBindAddress {
                addr: [127, 0, 0, 1].into(),
                port_range: 5678..6789,
            };
            assert!(
                format!("{error}").contains("Cannot bind to 127.0.0.1 on any port from 5678-6788")
            )
        }
    }

    mod server_error {
        use crate::ServerError;
        use poem::error::ResponseError;
        use poem::http::StatusCode;
        use std::io;
        use std::io::ErrorKind;

        #[test]
        fn no_result_response_error_trait() {
            let response = ServerError::NoResult.as_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[test]
        fn internal_server_error_response_error_trait() {
            let io_error = io::Error::from(ErrorKind::AddrInUse);
            let response = ServerError::InternalServerError(io_error).as_response();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    mod auth_error {
        use crate::AuthError;

        #[test]
        fn csrf_mismatch() {
            assert!(format!("{}", AuthError::CsrfMismatch)
                .contains("Invalid CSRF token (state parameter)"));
        }

        #[test]
        fn invalid_auth_state() {
            assert!(format!("{}", AuthError::InvalidAuthState)
                .contains("No authorization code or PKCE verifier present"));
        }
    }
}
