//! OAuth 2.0 helper for CLI and desktop applications.
//!
//! Facilitates the [OAuth 2.0 Authorization Code with PKCE][1] flow. This package works
//! hand-in-hand with the [oauth2][2] crate.
//!
//! # Usage
//!
//! General usage is as follows:
//!
//! 1. Configure an [`oauth2::Client`]
//! 1. Configure a [`CliOAuthBuilder`]
//! 1. Build and start the [`CliOAuth`]
//! 1. Await the token result
//!
//! # Examples
//!
//! _TODO: Examples for creating the oauth2 client, configuring the builder, starting the server,
//! and awaiting the token._
//!
//! [1]: https://www.rfc-editor.org/rfc/rfc7636
//! [2]: https://crates.io/crates/oauth2

use log::debug;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use oauth2::{
    AuthorizationCode, CsrfToken, ErrorResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RevocableToken, TokenIntrospectionResponse, TokenResponse, TokenType,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use url::Url;

use crate::builder::CliOAuthBuilder;

use crate::error::ServerError;
use crate::error::ServerError::NoResult;
use crate::error::{AuthError, ConfigError};
use crate::server::launch;
use crate::ConfigError::CannotBindAddress;

mod builder;
mod error;
mod server;

/// A shortcut [`Result`] using an error of [`ConfigError`].
pub type ConfigResult<T> = Result<T, ConfigError>;
/// A shortcut [`Result`] using an error of [`ServerError`].
type AuthorizationResultHolder = Arc<Mutex<Option<AuthorizationResult>>>;

/// The CLI OAuth helper.
#[derive(Debug)]
pub struct CliOAuth {
    address: SocketAddr,
    timeout: u64,
    auth_context: Option<AuthContext>,
    auth_result: Option<AuthorizationResult>,
}

impl CliOAuth {
    pub fn builder() -> CliOAuthBuilder {
        CliOAuthBuilder::new()
    }

    pub fn redirect_url(&self) -> RedirectUrl {
        let url = format!("http://{}", self.address);
        RedirectUrl::from_url(Url::parse(&url).unwrap())
    }

    pub async fn authorize<TE, TR, TT, TIR, RT, TRE>(
        &mut self,
        oauth_client: &oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    ) -> Result<(), ServerError>
    where
        TE: ErrorResponse + 'static,
        TR: TokenResponse<TT>,
        TT: TokenType,
        TIR: TokenIntrospectionResponse<TT>,
        RT: RevocableToken,
        TRE: ErrorResponse + 'static,
    {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, state) = oauth_client
            .authorize_url(CsrfToken::new_random)
            // This is where we need to set scopes on the request
            // TODO Add scope configuration to Builder
            .set_pkce_challenge(pkce_challenge)
            .url();
        // Create communication channels
        let (control_sender, control_receiver) = mpsc::channel(1);

        // Acquire handle to Tokio runtime
        let handle = Handle::try_current()?;
        let result = AuthorizationResultHolder::new(Mutex::new(None));
        let server = handle.spawn(launch(
            self.address.clone(),
            Arc::clone(&result),
            control_sender.clone(),
            control_receiver,
            self.timeout,
        ));

        debug!("🔑 authorization URL: {}", auth_url);
        open::that(auth_url.as_str())?;

        server.await?;

        let AuthorizationResult {
            auth_code,
            state: state_in,
        } = match &mut *result.lock().unwrap() {
            Some(auth_result) => auth_result.clone(),
            None => return Err(NoResult),
        };
        self.auth_result = Some(AuthorizationResult {
            auth_code: auth_code.clone(),
            state: state_in.clone(),
        });

        let auth_ctx = AuthContext {
            auth_code: AuthorizationCode::new(String::from(auth_code.clone())),
            state,
            pkce_verifier,
        };
        self.auth_context = Some(auth_ctx);

        Ok(())
    }

    pub fn validate(&mut self) -> Result<AuthContext, AuthError> {
        let expected_state = self.auth_result.take().ok_or(AuthError::NoResult)?.state;
        match self.auth_context.take() {
            Some(auth_ctx) if auth_ctx.state.secret() == &expected_state => Ok(auth_ctx),
            Some(_) => Err(AuthError::CsrfMismatch),
            None => Err(AuthError::NoResult),
        }
    }
}

#[derive(Debug)]
pub struct AuthContext {
    pub auth_code: AuthorizationCode,
    pub state: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
}

#[derive(Clone)]
struct AuthorizationResult {
    pub auth_code: String,
    pub state: String,
}

impl Debug for AuthorizationResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "auth code={}*****, state={}*****",
            self.auth_code.chars().take(3).collect::<String>(),
            self.state.chars().take(3).collect::<String>(),
        ))
    }
}

const PORT_MIN: u16 = 1024;
const DEFAULT_PORT_MIN: u16 = 3456;
const DEFAULT_PORT_MAX: u16 = DEFAULT_PORT_MIN + 10;
const DEFAULT_TIMEOUT: u64 = 60;

fn find_available_port(ip_addr: IpAddr, port_range: Range<u16>) -> ConfigResult<SocketAddr> {
    for port in port_range.clone() {
        let socket_addr = SocketAddr::new(ip_addr, port);
        let bind_res = TcpListener::bind(socket_addr);
        if bind_res.is_ok() {
            return Ok(socket_addr);
        }
    }
    Err(CannotBindAddress {
        addr: ip_addr,
        port_range,
    })
}

fn is_address_available(socket_addr: SocketAddr) -> bool {
    match TcpListener::bind(socket_addr) {
        Ok(_) => true,
        Err(_) => false,
    }
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// NOTE! The tests below all use different ports/port ranges, because the order of the tests
// cannot be guaranteed. If the ports overlap, then tests will fail randomly. Make sure that any
// future tests use their own unique port values. The best way to do that is with the `next_ports`
// function to acquire a range of ports for the test.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::atomic::AtomicU16;
    use std::sync::atomic::Ordering::AcqRel;

    use rstest::rstest;

    use crate::{find_available_port, is_address_available};

    pub(crate) static LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    pub(crate) static PORT_GENERATOR: AtomicU16 = AtomicU16::new(8000);

    /// Acquires a range of ports for a test.
    ///
    /// Any test that needs to perform testing with network ports should call this method at the
    /// beginning to get the next start and end ports for the test:
    ///
    /// ```
    /// let (port_start, port_end) = next_ports(5);
    /// ```
    ///
    /// The function is backed by an atomic integer, so each test is guaranteed to get a unique
    /// range.
    pub(crate) fn next_ports(count: u16) -> (u16, u16) {
        let start = PORT_GENERATOR.fetch_add(count, AcqRel);
        let end = start + count - 1;
        (start, end)
    }

    #[rstest]
    fn find_available_port_with_open_port() {
        let (port_start, port_end) = next_ports(3);
        let res = find_available_port(LOCALHOST, port_start..port_end);
        match res {
            Ok(addr) => assert!((port_start..port_end).contains(&addr.port())),
            Err(e) => panic!("error finding available port: {:?}", e),
        }
    }

    #[rstest]
    fn find_available_port_with_no_open_port() {
        let (port_start, port_end) = next_ports(2);
        // Acquire sockets on both ports we need
        let _s1 = TcpListener::bind(SocketAddr::new(LOCALHOST, port_start)).unwrap();
        let _s2 = TcpListener::bind(SocketAddr::new(LOCALHOST, port_end)).unwrap();
        let res = find_available_port(LOCALHOST, port_start..port_end);
        res.expect_err("ports should not be available");
    }

    #[rstest]
    fn check_address_is_available_when_port_is_open() {
        let (test_port, open_port) = next_ports(2);
        let _sock = TcpListener::bind(SocketAddr::new(LOCALHOST, open_port))
            .expect("control port {open_port} is already open");
        let address = SocketAddr::new(LOCALHOST, test_port);
        assert!(is_address_available(address));
    }

    #[rstest]
    fn check_address_is_not_available_when_port_is_used() {
        let (test_port, open_port) = next_ports(1);
        let _socket =
            TcpListener::bind(SocketAddr::new(LOCALHOST, open_port)).expect("port is already open");
        let address = SocketAddr::new(LOCALHOST, test_port);
        assert!(!is_address_available(address));
    }
}
