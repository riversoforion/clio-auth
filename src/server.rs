use std::marker::PhantomData;
use std::net::SocketAddr;

use oauth2::{TokenResponse, TokenType};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {}

pub(crate) type ServerResult<T> = Result<T, ServerError>;

pub(crate) struct AuthServer {}

impl AuthServer {
    pub(crate) async fn start(_addr: SocketAddr) -> ServerResult<AuthServer> {
        Ok(AuthServer {})
    }

    pub(crate) async fn get_tokens(self) -> ServerResult<()> {
        todo!()
    }
}
