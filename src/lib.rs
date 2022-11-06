use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::ops::Range;

use oauth2::{ErrorResponse, RevocableToken, TokenIntrospectionResponse, TokenResponse, TokenType};
use thiserror::Error;

use ConfigError::{CannotBindAddress, InvalidServerConfig};

/// Defines the various types of errors that can occur during the OAuth flow.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid server config (expected {expected}, found {found})")]
    InvalidServerConfig { expected: String, found: String },
    #[error("cannot bind to {addr} on any port from {}-{}", port_range.start, port_range.end - 1)]
    CannotBindAddress {
        addr: IpAddr,
        port_range: Range<u16>,
    },
}

/// A shortcut Result where the type of error is [`ConfigError`].
pub type ConfigResult<T> = Result<T, ConfigError>;

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
    _oauth_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    _address: SocketAddr,
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
    pub fn build(
        oauth: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    ) -> CliOAuthBuilder<TE, TR, TT, TIR, RT, TRE> {
        CliOAuthBuilder::new(oauth)
    }
    pub async fn start(&self) {}
}

const PORT_MIN: u16 = 1024;
const DEFAULT_PORT_MIN: u16 = 3000;
const DEFAULT_PORT_MAX: u16 = 3010;

/// A builder for [`ClioAuth`].
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
        }
    }

    fn resolve_address(&self) -> ConfigResult<SocketAddr> {
        match self.socket_address {
            Some(socket_addr) if is_address_available(socket_addr) => Ok(socket_addr),
            Some(socket_addr) => Err(CannotBindAddress {
                addr: socket_addr.ip(),
                port_range: socket_addr.port()..socket_addr.port(),
            }),
            None => find_available_port(self.ip_address.clone(), self.port_range.clone()),
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

    pub fn port(mut self, port: u16) -> Self {
        self.port_range = port..(port + 1);
        self
    }

    pub fn port_range(mut self, ports: Range<u16>) -> Self {
        self.port_range = ports;
        self
    }

    pub fn ip_address(mut self, ip_address: impl Into<IpAddr>) -> Self {
        self.ip_address = ip_address.into();
        self
    }

    pub fn socket_address(mut self, address: SocketAddr) -> Self {
        self.socket_address = Some(address);
        self
    }

    pub fn build(self) -> ConfigResult<CliOAuth<TE, TR, TT, TIR, RT, TRE>> {
        Ok(CliOAuth {
            _oauth_client: self.oauth_client,
            _address: self.socket_address.unwrap(),
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

    #[test]
    #[ignore]
    fn socket_harness() {
        let (port_start, port_end) = next_ports(6);
        let _s1 = TcpListener::bind(SocketAddr::new(LOCALHOST, port_start + 1));
        let _s2 = TcpListener::bind(SocketAddr::new(LOCALHOST, port_start + 3));
        for port in port_start..port_end {
            let addr = SocketAddr::new(LOCALHOST, port);
            if is_address_available(addr) {
                print!("Port :{port} is available...  ");
            } else {
                eprint!("Port :{port} NOT available... ");
            }
            match TcpListener::bind(addr) {
                Ok(_) => println!("Socket acquired on :{port}"),
                Err(e) => eprintln!("Socket failed on :{port} : {:?}", e),
            }
            println!();
        }
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
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::str::FromStr;

        use oauth2::basic::BasicClient;
        use oauth2::{AuthUrl, ClientId, RedirectUrl, TokenUrl};
        use rstest::{fixture, rstest};

        use crate::tests::{next_ports, LOCALHOST};
        use crate::{CliOAuthBuilder, DEFAULT_PORT_MAX, DEFAULT_PORT_MIN, PORT_MIN};

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
    }
}
