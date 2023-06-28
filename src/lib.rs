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

use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use oauth2::{ErrorResponse, RevocableToken, TokenIntrospectionResponse, TokenResponse, TokenType};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::builder::CliOAuthBuilder;

use crate::error::ConfigError;
use crate::error::ServerError;
use crate::server::launch;
use crate::ConfigError::CannotBindAddress;

mod builder;
mod error;
mod server;

/// A shortcut [`Result`] using an error of [`ConfigError`].
pub type ConfigResult<T> = Result<T, ConfigError>;
/// A shortcut [`Result`] using an error of [`ServerError`].
pub type ServerResult<T> = Result<T, ServerError>;
type AuthorizationContextHolder = Arc<Mutex<Option<AuthorizationContext>>>;

/// The CLI OAuth helper.
#[derive(Debug)]
pub struct CliOAuth<TE, TR, TT, TIR, RT, TRE>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse,
{
    oauth_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    address: SocketAddr,
    timeout: u64,
    token: Option<TR>,
}

impl<TE, TR, TT, TIR, RT, TRE> CliOAuth<TE, TR, TT, TIR, RT, TRE>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse,
{
    pub fn builder(
        oauth_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    ) -> CliOAuthBuilder<TE, TR, TT, TIR, RT, TRE> {
        CliOAuthBuilder::new(oauth_client)
    }

    pub async fn fetch_auth_code(&mut self) -> ServerResult<()> {
        // TODO Enrich OAuth client with challenge, state, and redirect URL
        // TODO Save state and challenge for later
        // Create communication channels
        let (control_sender, control_receiver) = mpsc::channel(1);

        // Acquire handle to Tokio runtime
        let handle = Handle::try_current()?;
        let server = handle.spawn(launch(
            self.address.clone(),
            AuthorizationContextHolder::new(Mutex::new(None)),
            control_sender.clone(),
            control_receiver,
            self.timeout,
        ));

        // TODO Open browser window to authorization link

        server.await?;

        // TODO Validate the state
        // TODO Exchange the auth code for a token
        todo!("Check for valid token")
    }

    pub async fn token(&self) -> Box<TR> {
        todo!()
    }
}

struct AuthorizationContext {
    pub auth_code: String,
    pub state: String,
}

impl Debug for AuthorizationContext {
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
