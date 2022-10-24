use oauth2::{ErrorResponse, RevocableToken, TokenIntrospectionResponse, TokenResponse, TokenType};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorType {}

pub type Result<T> = std::result::Result<T, ErrorType>;

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
    port_range: Option<Range<u16>>,
    ip_address: Option<IpAddr>,
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
            port_range: Some(3000..3009_u16),
            ip_address: Some(IpAddr::V4([127, 0, 0, 1].into())),
            socket_address: None,
        }
    }

    pub fn with_port(&self, port: u16) -> &Self {
        self
    }

    pub fn with_port_range(&self, ports: Range<u16>) -> &Self {
        self
    }

    pub fn with_ip_address(&self, ip_address: impl Into<IpAddr>) -> &Self {
        self
    }

    pub fn with_socket_address(&self, address: SocketAddr) -> &Self {
        self
    }

    pub fn start(self) -> Result<CliOAuth<TE, TR, TT, TIR, RT, TRE>> {
        Ok(CliOAuth {
            oauth_client: self.oauth_client,
            address: self.socket_address.unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    mod builder {
        #[rstest]
        fn all_defaults() {}
    }
}
