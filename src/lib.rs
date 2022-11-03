use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;

use oauth2::{ErrorResponse, RevocableToken, TokenIntrospectionResponse, TokenResponse, TokenType};
use thiserror::Error;

/// Defines the various types of errors that can occur during the OAuth flow.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid server config (expected {expected}, found {found})")]
    InvalidServerConfig { expected: String, found: String },
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
    oauth_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    address: SocketAddr,
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

    fn validate(&self) -> ConfigResult<()> {
        if self.port_range.start < PORT_MIN {
            return Err(ConfigError::InvalidServerConfig {
                expected: format!("port >= {}", PORT_MIN),
                found: format!("{}", self.port_range.start),
            });
        }
        Ok(())
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port_range = port..port;
        self
    }

    pub fn with_port_range(mut self, ports: Range<u16>) -> Self {
        self.port_range = ports;
        self
    }

    pub fn with_ip_address(mut self, ip_address: impl Into<IpAddr>) -> Self {
        self.ip_address = ip_address.into();
        self
    }

    pub fn with_socket_address(mut self, address: SocketAddr) -> Self {
        self.socket_address = Some(address);
        self
    }

    pub fn start(self) -> ConfigResult<CliOAuth<TE, TR, TT, TIR, RT, TRE>> {
        Ok(CliOAuth {
            oauth_client: self.oauth_client,
            address: self.socket_address.unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    mod builder {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use oauth2::basic::BasicClient;
        use oauth2::{AuthUrl, ClientId, RedirectUrl, TokenUrl};
        use rstest::{fixture, rstest};

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
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn set_single_port(oauth_client: BasicClient) {
            let port = 2048;
            let builder = CliOAuthBuilder::new(oauth_client).with_port(port);
            assert_eq!(builder.port_range.clone(), port..port);
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        #[case::one_less_than_min(PORT_MIN - 1)]
        #[case::one(1)]
        #[case::zero(0)]
        fn set_single_invalid_port(oauth_client: BasicClient, #[case] port: u16) {
            let builder = CliOAuthBuilder::new(oauth_client).with_port(port);
            let result = builder.validate();
            let error = result.expect_err("Port should be invalid");
            assert_eq!(
                format!("{error}"),
                format!("invalid server config (expected port >= 1024, found {port})")
            );
        }

        #[rstest]
        fn set_port_range(oauth_client: BasicClient) {
            let port_range = 2048..4096;
            let builder = CliOAuthBuilder::new(oauth_client).with_port_range(port_range.clone());
            assert_eq!(builder.port_range.clone(), port_range);
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn set_ip_address(oauth_client: BasicClient) {
            use std::str::FromStr;

            let builder = CliOAuthBuilder::new(oauth_client)
                .with_ip_address(IpAddr::V4(Ipv4Addr::from_str("192.168.0.20").unwrap()));
            assert_eq!(
                builder.ip_address.clone(),
                Ipv4Addr::from([192, 168, 0, 20])
            );
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn set_socket_address(oauth_client: BasicClient) {
            use std::str::FromStr;

            let addr = SocketAddr::from_str("192.168.0.20:4096").unwrap();
            let builder = CliOAuthBuilder::new(oauth_client).with_socket_address(addr.clone());
            assert_eq!(builder.socket_address.clone().unwrap(), addr);
            builder.validate().expect("builder should be valid");
        }

        #[rstest]
        fn socket_address_overrides_ip_and_port() {}
    }
}
