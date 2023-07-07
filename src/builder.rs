use oauth2::Scope;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::ConfigError::{CannotBindAddress, InvalidServerConfig};
use crate::*;

/// A builder for [`CliOAuth`] structs.
///
/// Not constructed directly. See [`CliOAuth::builder()`].
#[derive(Debug)]
pub struct CliOAuthBuilder {
    port_range: PortRange,
    ip_address: IpAddr,
    socket_address: Option<SocketAddr>,
    timeout: u64,
    scopes: Vec<Scope>,
}

impl CliOAuthBuilder {
    pub(crate) fn new() -> Self {
        CliOAuthBuilder {
            port_range: DEFAULT_PORT_MIN..DEFAULT_PORT_MAX,
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            socket_address: None,
            timeout: DEFAULT_TIMEOUT,
            scopes: Default::default(),
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
    /// For simplicity, must be a non-privileged port (greater than or equal to `1024`).
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
    pub fn port_range(mut self, ports: PortRange) -> Self {
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

    /// Adds a scope to include with the authorization request.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scopes.push(scope);
        self
    }

    /// Adds scopes to include with the authorization request.
    pub fn scopes<S>(mut self, scopes: S) -> Self
    where
        S: IntoIterator<Item = Scope>,
    {
        self.scopes.extend(scopes);
        self
    }

    /// Constructs the [`CliOAuth`] instance with the configuration captured in this builder.
    pub fn build(self) -> ConfigResult<CliOAuth> {
        self.validate()?;
        let socket_addr = self.resolve_address()?;
        Ok(CliOAuth {
            address: socket_addr,
            timeout: self.timeout,
            scopes: self.scopes,
            auth_context: None,
            auth_result: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use oauth2::Scope;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::str::FromStr;

    use rstest::rstest;

    use super::CliOAuthBuilder;
    use crate::tests::{next_ports, LOCALHOST};
    use crate::{DEFAULT_PORT_MAX, DEFAULT_PORT_MIN, DEFAULT_TIMEOUT, PORT_MIN};

    #[rstest]
    fn all_defaults() {
        let builder = CliOAuthBuilder::new();
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
    fn set_single_port() {
        let port = 2048;
        let builder = CliOAuthBuilder::new().port(port);
        assert!(builder.port_range.contains(&port));
        builder.validate().expect("builder should be valid");
    }

    #[rstest]
    #[case::one_less_than_min(PORT_MIN - 1)]
    #[case::one(1)]
    #[case::zero(0)]
    fn set_single_invalid_port(#[case] port: u16) {
        let builder = CliOAuthBuilder::new().port(port);
        let error = builder.validate().expect_err("Port should be invalid");
        assert_eq!(
            format!("{error}"),
            format!("Invalid server config (expected port >= 1024, found {port})")
        );
    }

    #[rstest]
    fn set_port_range() {
        let port_range = 2048..4096;
        let builder = CliOAuthBuilder::new().port_range(port_range.clone());
        assert_eq!(builder.port_range.clone(), port_range);
        builder.validate().expect("builder should be valid");
    }

    #[rstest]
    #[case::one_less_than_min(PORT_MIN - 1)]
    #[case::one(1)]
    #[case::zero(0)]
    fn set_invalid_port_range(#[case] lower_port: u16) {
        let builder = CliOAuthBuilder::new().port_range(lower_port..PORT_MIN);
        let error = builder
            .validate()
            .expect_err("Port range should be invalid");
        assert_eq!(
            format!("{error}"),
            format!("Invalid server config (expected port >= 1024, found {lower_port})")
        );
    }

    #[rstest]
    fn set_ip_address() {
        let builder = CliOAuthBuilder::new()
            .ip_address(IpAddr::V4(Ipv4Addr::from_str("192.168.0.20").unwrap()));
        assert_eq!(
            builder.ip_address.clone(),
            Ipv4Addr::from([192, 168, 0, 20])
        );
        builder.validate().expect("builder should be valid");
    }

    #[rstest]
    fn set_socket_address() {
        let addr = SocketAddr::from_str("192.168.0.20:4096").unwrap();
        let builder = CliOAuthBuilder::new().socket_address(addr);
        assert_eq!(builder.socket_address.unwrap(), addr);
        builder.validate().expect("builder should be valid");
    }

    #[rstest]
    fn socket_address_overrides_ip_and_port() {
        let (start_port, end_port) = next_ports(5);
        let port_range = start_port..end_port;
        let socket_addr = SocketAddr::from_str("127.0.0.1:8192").unwrap();

        let builder = CliOAuthBuilder::new()
            .ip_address(LOCALHOST)
            .port_range(port_range.clone())
            .socket_address(socket_addr);
        let resolved_address = builder.resolve_address().unwrap();
        assert_eq!(resolved_address, socket_addr);
    }

    #[rstest]
    fn socket_address_from_ip_and_port_range() {
        let (port, _) = next_ports(1);
        let builder = CliOAuthBuilder::new().ip_address(LOCALHOST).port(port);
        let resolved_address = builder.resolve_address().unwrap();
        assert_eq!(resolved_address.port(), port);
        assert_eq!(resolved_address.ip(), LOCALHOST);
    }

    #[rstest]
    fn set_timeout() {
        let builder = CliOAuthBuilder::new().timeout(120);
        assert_eq!(builder.timeout, 120);
    }

    #[rstest]
    fn add_scope() {
        let builder = CliOAuthBuilder::new().scope(Scope::new(String::from("test_scope")));
        assert_eq!(builder.scopes, vec![Scope::new(String::from("test_scope"))]);
    }

    #[rstest]
    fn add_scopes() {
        let scopes = vec![
            Scope::new(String::from("scope:1")),
            Scope::new(String::from("scope:2")),
        ];
        let builder = CliOAuthBuilder::new().scopes(scopes);
        assert_eq!(
            builder.scopes,
            vec![
                Scope::new(String::from("scope:1")),
                Scope::new(String::from("scope:2"))
            ]
        );
    }

    #[rstest]
    fn build_valid_struct() {
        let (port, _) = next_ports(1);
        let builder = CliOAuthBuilder::new().port(port).timeout(30);
        let res = builder.build();
        let auth = res.expect("valid struct should be built");
        let built_addr = auth.address;
        assert_eq!(built_addr, SocketAddr::new(LOCALHOST, port));
        assert_eq!(auth.timeout, 30);
    }

    #[rstest]
    fn build_struct_with_invalid_ports() {
        let port = 26;
        let builder = CliOAuthBuilder::new().port(port);
        let res = builder.build();
        let error = res.expect_err("error should be returned");
        assert_eq!(
            format!("{error}"),
            format!("Invalid server config (expected port >= 1024, found {port})")
        );
    }

    #[rstest]
    fn build_struct_with_unavailable_ports() {
        let (test_port, open_port) = next_ports(1);
        let _socket =
            TcpListener::bind(SocketAddr::new(LOCALHOST, open_port)).expect("port is already open");
        let builder = CliOAuthBuilder::new().port(test_port);
        let res = builder.build();
        let error = res.expect_err("error should be returned");
        assert_eq!(
            format!("{error}"),
            format!("Cannot bind to 127.0.0.1 on any port from {test_port}-{test_port}")
        );
    }
}
