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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use oauth2::{ErrorResponse, RevocableToken, TokenIntrospectionResponse, TokenResponse, TokenType};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

pub use error::ConfigError;

use crate::error::ServerError;
use crate::server::launch;
use crate::ConfigError::{CannotBindAddress, InvalidServerConfig};

mod error;
mod server;

/// A shortcut [`Result`] using an error of [`ConfigError`].
pub type ConfigResult<T> = Result<T, ConfigError>;
/// A shortcut [`Result`] using an error of [`ServerError`].
pub type ServerResult<T> = Result<T, ServerError>;
type AuthCodeHolder = Arc<Mutex<Option<String>>>;

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
    auth_code: Option<String>,
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
        // Create holder for the OAuth auth code
        let auth_code_holder: AuthCodeHolder = Arc::new(Mutex::new(None));
        // Create communication channels
        let (control_sender, control_receiver) = mpsc::channel(1);

        // Acquire handle to Tokio runtime
        let handle = Handle::try_current()?;
        let server = handle.spawn(launch(
            self.address.clone(),
            auth_code_holder.clone(),
            control_sender.clone(),
            control_receiver,
            self.timeout,
        ));

        server.await?;

        let result = auth_code_holder.lock().unwrap();
        match result.as_ref() {
            Some(res) => {
                self.auth_code = Some(res.to_owned());
                Ok(())
            },
            None => Err(ServerError::NoResult),
        }
    }

    pub async fn token(&self) -> Box<TR> {
        todo!()
    }
}

const PORT_MIN: u16 = 1024;
const DEFAULT_PORT_MIN: u16 = 3456;
const DEFAULT_PORT_MAX: u16 = DEFAULT_PORT_MIN + 10;
const DEFAULT_TIMEOUT: u64 = 60;

/// A builder for [`CliOAuth`] structs.
///
/// Not constructed directly. See [`CliOAuth::builder()`].
#[derive(Debug)]
pub struct CliOAuthBuilder<TE, TR, TT, TIR, RT, TRE>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse,
{
    oauth_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    port_range: Range<u16>,
    ip_address: IpAddr,
    socket_address: Option<SocketAddr>,
    timeout: u64,
}

impl<TE, TR, TT, TIR, RT, TRE> CliOAuthBuilder<TE, TR, TT, TIR, RT, TRE>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse,
{
    fn new(oauth_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>) -> Self {
        CliOAuthBuilder {
            oauth_client,
            port_range: DEFAULT_PORT_MIN..DEFAULT_PORT_MAX,
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            socket_address: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn resolve_address(&self) -> ConfigResult<SocketAddr> {
        match self.socket_address {
            Some(socket_addr) if is_address_available(socket_addr) => Ok(socket_addr),
            Some(socket_addr) => Err(CannotBindAddress {
                addr: socket_addr.ip(),
                port_range: socket_addr.port()..socket_addr.port(),
            }),
            None => find_available_port(self.ip_address, self.port_range.clone()),
        }
    }

    fn validate(&self) -> ConfigResult<()> {
        if self.port_range.start < PORT_MIN {
            return Err(InvalidServerConfig {
                expected: format!("port >= {}", PORT_MIN),
                found: format!("{}", self.port_range.start),
            });
        }
        Ok(())
    }

    /// Configures a single port for the web server to attempt to bind to.
    ///
    /// For simplicity, must be a non-privileged port (greater that or equal to `1024`).
    pub fn port(mut self, port: u16) -> Self {
        self.port_range = port..(port + 1);
        self
    }

    /// Configures a range of ports for the web server to attempt to bind to.
    ///
    /// When the `CliOAuth` instance is constructed, each of these ports will be tried in order. The
    /// first open one will be used.
    ///
    /// The default range is `3456..3465`.
    pub fn port_range(mut self, ports: Range<u16>) -> Self {
        self.port_range = ports;
        self
    }

    /// Configures the local IP address for the web server to listen on.
    ///
    /// Address must be configured for the system. The default is "localhost" (`127.0.0.1`), which
    /// works fine in most cases.
    pub fn ip_address(mut self, ip_address: impl Into<IpAddr>) -> Self {
        self.ip_address = ip_address.into();
        self
    }

    /// Configures a socket address (IP address and port) for the web server to listen on.
    ///
    /// If provided, it overrides the [`Self::ip_address()`], [`Self::port()`], and
    /// [`Self::port_range()`] settings.
    pub fn socket_address(mut self, address: SocketAddr) -> Self {
        self.socket_address = Some(address);
        self
    }

    /// Configures the number of seconds the server will wait for an authorization code.
    ///
    /// If the server has not received a request containing a valid authorization code, it will
    /// shut itself down, and the token exchange will not be possible.
    ///
    /// The default is `60` seconds.
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Constructs the [`CliOAuth`] instance.
    pub fn build(self) -> ConfigResult<CliOAuth<TE, TR, TT, TIR, RT, TRE>> {
        self.validate()?;
        let socket_addr = self.resolve_address()?;
        Ok(CliOAuth {
            oauth_client: self.oauth_client,
            address: socket_addr,
            timeout: self.timeout,
            auth_code: None,
            token: None,
        })
    }
}

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

    static LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    static PORT_GENERATOR: AtomicU16 = AtomicU16::new(8000);

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
    fn next_ports(count: u16) -> (u16, u16) {
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

    mod builder {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
        use std::str::FromStr;

        use oauth2::basic::BasicClient;
        use oauth2::{AuthUrl, ClientId, RedirectUrl, TokenUrl};
        use rstest::{fixture, rstest};

        use crate::tests::{next_ports, LOCALHOST};
        use crate::{
            CliOAuth, CliOAuthBuilder, DEFAULT_PORT_MAX, DEFAULT_PORT_MIN, DEFAULT_TIMEOUT,
            PORT_MIN,
        };

        #[fixture]
        fn oauth_client() -> BasicClient {
            BasicClient::new(
                ClientId::new("1234".into()),
                None,
                AuthUrl::new("https://auth.example.com/auth".into()).unwrap(),
                Some(TokenUrl::new("https://auth.example.com/token".into()).unwrap()),
            )
            .set_redirect_uri(RedirectUrl::new("https://localhost:9000".into()).unwrap())
        }

        #[rstest]
        fn all_defaults(oauth_client: BasicClient) {
            let builder = CliOAuthBuilder::new(oauth_client);
            assert_eq!(
                builder.port_range.clone(),
                DEFAULT_PORT_MIN..DEFAULT_PORT_MAX
            );
            assert_eq!(builder.ip_address.clone(), LOCALHOST);
            assert_eq!(builder.socket_address.clone(), None);
            assert_eq!(builder.timeout, DEFAULT_TIMEOUT);
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn set_single_port(oauth_client: BasicClient) {
            let port = 2048;
            let builder = CliOAuthBuilder::new(oauth_client).port(port);
            assert!(builder.port_range.contains(&port));
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        #[case::one_less_than_min(PORT_MIN - 1)]
        #[case::one(1)]
        #[case::zero(0)]
        fn set_single_invalid_port(oauth_client: BasicClient, #[case] port: u16) {
            let builder = CliOAuthBuilder::new(oauth_client).port(port);
            let error = builder.validate().expect_err("Port should be invalid");
            assert_eq!(
                format!("{error}"),
                format!("invalid server config (expected port >= 1024, found {port})")
            );
        }

        #[rstest]
        fn set_port_range(oauth_client: BasicClient) {
            let port_range = 2048..4096;
            let builder = CliOAuthBuilder::new(oauth_client).port_range(port_range.clone());
            assert_eq!(builder.port_range.clone(), port_range);
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        #[case::one_less_than_min(PORT_MIN - 1)]
        #[case::one(1)]
        #[case::zero(0)]
        fn set_invalid_port_range(oauth_client: BasicClient, #[case] lower_port: u16) {
            let builder = CliOAuthBuilder::new(oauth_client).port_range(lower_port..PORT_MIN);
            let error = builder
                .validate()
                .expect_err("Port range should be invalid");
            assert_eq!(
                format!("{error}"),
                format!("invalid server config (expected port >= 1024, found {lower_port})")
            );
        }

        #[rstest]
        fn set_ip_address(oauth_client: BasicClient) {
            let builder = CliOAuthBuilder::new(oauth_client)
                .ip_address(IpAddr::V4(Ipv4Addr::from_str("192.168.0.20").unwrap()));
            assert_eq!(
                builder.ip_address.clone(),
                Ipv4Addr::from([192, 168, 0, 20])
            );
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn set_socket_address(oauth_client: BasicClient) {
            let addr = SocketAddr::from_str("192.168.0.20:4096").unwrap();
            let builder = CliOAuthBuilder::new(oauth_client).socket_address(addr);
            assert_eq!(builder.socket_address.unwrap(), addr);
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn socket_address_overrides_ip_and_port(oauth_client: BasicClient) {
            let (start_port, end_port) = next_ports(5);
            let port_range = start_port..end_port;
            let socket_addr = SocketAddr::from_str("127.0.0.1:8192").unwrap();

            let builder = CliOAuthBuilder::new(oauth_client)
                .ip_address(LOCALHOST)
                .port_range(port_range.clone())
                .socket_address(socket_addr);
            let resolved_address = builder.resolve_address().unwrap();
            assert_eq!(resolved_address, socket_addr);
        }

        #[rstest]
        fn socket_address_from_ip_and_port_range(oauth_client: BasicClient) {
            let (port, _) = next_ports(1);
            let builder = CliOAuthBuilder::new(oauth_client)
                .ip_address(LOCALHOST)
                .port(port);
            let resolved_address = builder.resolve_address().unwrap();
            assert_eq!(resolved_address.port(), port);
            assert_eq!(resolved_address.ip(), LOCALHOST);
        }

        #[rstest]
        fn set_timeout(oauth_client: BasicClient) {
            let builder = CliOAuthBuilder::new(oauth_client).timeout(120);
            assert_eq!(builder.timeout, 120);
        }

        #[rstest]
        fn build_valid_struct(oauth_client: BasicClient) {
            let (port, _) = next_ports(1);
            let builder = CliOAuthBuilder::new(oauth_client).port(port).timeout(30);
            let res = builder.build();
            let auth = res.expect("valid struct should be built");
            let built_addr = auth.address;
            assert_eq!(built_addr, SocketAddr::new(LOCALHOST, port));
            assert_eq!(auth.timeout, 30);
        }

        #[rstest]
        fn build_struct_with_invalid_ports(oauth_client: BasicClient) {
            let port = 26;
            let builder = CliOAuthBuilder::new(oauth_client).port(port);
            let res = builder.build();
            let error = res.expect_err("error should be returned");
            assert_eq!(
                format!("{error}"),
                format!("invalid server config (expected port >= 1024, found {port})")
            );
        }

        #[rstest]
        fn build_struct_with_unavailable_ports(oauth_client: BasicClient) {
            let (test_port, open_port) = next_ports(1);
            let _socket = TcpListener::bind(SocketAddr::new(LOCALHOST, open_port))
                .expect("port is already open");
            let builder = CliOAuthBuilder::new(oauth_client).port(test_port);
            let res = builder.build();
            let error = res.expect_err("error should be returned");
            assert_eq!(
                format!("{error}"),
                format!("cannot bind to 127.0.0.1 on any port from {test_port}-{test_port}")
            );
        }
    }
}
