//! OAuth 2.0 helper for CLI and desktop applications.
//!
//! This package facilitates the [OAuth 2.0 Authorization Code with PKCE][1] flow for command line
//! and desktop GUI applications. This package works hand-in-hand with the [oauth2][2] crate by providing the "missing
//! pieces" for the flow: a web server to handle the authorization callback, and opening the browser with the
//! authorization link.
//!
//! # Usage
//!
//! General usage is as follows:
//!
//! 1. Configure and build a [`CliOAuthBuilder`]
//! 1. Configure an [`oauth2::Client`]
//! 1. Start the [authorization flow](CliOAuth::authorize)
//! 1. [Validate and obtain](CliOAuth::validate) the authorization code
//! 1. [Exchange the code](oauth2::Client::exchange_code) for a token
//!
//! # Examples
//!
//! This example is adapted directly from the [`oauth2`] package documentation ("Asynchronous API"),
//! and demonstrates how `CliOAuth` fills in the gaps.
//!
//! ```no_run
//! use anyhow;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     PkceCodeChallenge,
//!     RedirectUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! # #[cfg(feature = "reqwest")]
//! use oauth2::reqwest::async_http_client;
//! use url::Url;
//!
//! # #[cfg(feature = "reqwest")]
//! # async fn err_wrapper() -> Result<(), anyhow::Error> {
//! // CliOAuth: Build helper with default options
//! let mut auth = clio_auth::CliOAuth::builder().build().unwrap();        // (1)
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     )
//!     // CliOAuth: Use the local redirect URL
//!     .set_redirect_uri(auth.redirect_url());                           // (2)
//!
//! // CliOAuth: The PKCE challenge is handled internally. Just authorize... (3)
//! match auth.authorize(&oauth_client).await {
//!     Ok(()) => info!("authorized successfully"),
//!     Err(e) => warn!("uh oh! {:?}", e),
//! };
//! // CliOAuth: The browser is opened to the authorization URL              (3)
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the
//! // authorization code. For security reasons, your code should verify that the `state`
//! // parameter returned by the server matches `csrf_state`.
//! // CliOAuth: Validation must be performed to acquire the authorization code
//! match auth.validate() {                                              // (4)
//!     Ok(AuthContext {
//!         auth_code,
//!         pkce_verifier,
//!         state: _,
//!     }) => {
//!         // Now you can trade it for an access token.
//!         let token_result = client
//!             .exchange_code(auth_code)                                // (5)
//!             // Set the PKCE code verifier.
//!             .set_pkce_verifier(pkce_verifier)
//!             .request_async(async_http_client)
//!             .await?;
//!         // Unwrapping token_result will either produce a Token or a RequestTokenError.
//!     },
//!     Err(e) => warn!("uh oh! {:?}", e),
//! }
//!
//! # Ok(())
//! # }
//! ```
//!
//! Let's break down the numbered comments:
//! 1. `CliOAuth` construction starts with a [builder](CliOAuthBuilder), which allows you to
//! customize the way the authorization helper is configured.
//! 2. `CliOAuth` constructs the authorization URL based on the address & port it is running on. The
//! URL is provided to the [`oauth2::Client`] during construction.
//! 3. Invoking the [`CliOAuth::authorize`] method will do the following things:
//!    - Launch a local web server
//!    - Generate the CSRF protection token (`state` parameter)
//!    - Open the user's browser with the URL to initiate the authorization flow
//!    - Receive the incoming authorization code
//!    - Shutdown the local web server
//! 4. Invoking the [`CliOAuth::validate`] method will verify that an auth code was received and
//! that the `state` parameter matches the expected value. If validation succeeds, the auth code and
//! PKCE verifier will be returned to the caller.
//! 5. The auth code and PKCE verifier are provided to the
//! [exchange code](oauth2::Client::exchange_code) flow.
//!
//! [1]: https://www.rfc-editor.org/rfc/rfc7636
//! [2]: https://crates.io/crates/oauth2

use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use log::debug;
use oauth2::{
    AuthorizationCode, CsrfToken, ErrorResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RevocableToken, Scope, TokenIntrospectionResponse, TokenResponse, TokenType,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use url::Url;

pub use crate::builder::CliOAuthBuilder;
use crate::error::ServerError::NoResult;
pub use crate::error::{AuthError, ConfigError, ServerError};
use crate::server::launch;
use crate::ConfigError::CannotBindAddress;

mod builder;
mod error;
mod server;

pub(crate) type PortRange = Range<u16>;
/// A shortcut [`Result`] using an error of [`ConfigError`].
pub type ConfigResult<T> = Result<T, ConfigError>;
type AuthorizationResultHolder = Arc<Mutex<Option<AuthorizationResult>>>;

/// The CLI OAuth helper.
#[derive(Debug)]
pub struct CliOAuth {
    address: SocketAddr,
    timeout: u64,
    scopes: Vec<Scope>,
    auth_context: Option<AuthContext>,
    auth_result: Option<AuthorizationResult>,
}

impl CliOAuth {
    /// Constructs a new builder struct for configuration.
    pub fn builder() -> CliOAuthBuilder {
        CliOAuthBuilder::new()
    }

    /// Generates the redirect URL that will sent in the authorization URL to the identity
    /// provider.
    ///
    /// Pass the result of this method to [`oauth2::Client::set_redirect_uri`] while building the
    /// client.
    pub fn redirect_url(&self) -> RedirectUrl {
        let url = format!("http://{}", self.address);
        RedirectUrl::from_url(Url::parse(&url).unwrap())
    }

    /// Initiates the Authorization Code flow.
    ///
    /// The PKCE challenge and verifier are generated. The challenge is used in the authorization
    /// URL, and the verifier is saved for the validation step.
    ///
    /// The authorization URL is then opened in the user's browser, and the redirect request is
    /// handled by recording the authorization code (`code`) and CSRF token (`state`). These values
    /// will also be used in the validation step, and then returned to the caller for the token
    /// exchange.
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
        let scopes: Vec<Scope> = self.scopes.to_vec();
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, state) = oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes)
            .set_pkce_challenge(pkce_challenge)
            .url();
        // Create communication channels
        let (control_sender, control_receiver) = mpsc::channel(1);

        // Acquire handle to Tokio runtime
        let handle = Handle::try_current()?;
        let result = AuthorizationResultHolder::new(Mutex::new(None));
        let server = handle.spawn(launch(
            self.address,
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
            auth_code: AuthorizationCode::new(auth_code.clone()),
            state,
            pkce_verifier,
        };
        self.auth_context = Some(auth_ctx);

        Ok(())
    }

    /// Validates the authorization code and CSRF token (`state`).
    ///
    /// If validation is successful, then the code and PKCE verifier are returned to the caller in
    /// order to build the [exchange code](oauth2::Client::exchange_code) request.
    ///
    /// This method *must* be called after [`CliOAuth::authorize`] completes successfully.
    pub fn validate(&mut self) -> Result<AuthContext, AuthError> {
        let expected_state = self
            .auth_result
            .take()
            .ok_or(AuthError::InvalidAuthState)?
            .state;
        match self.auth_context.take() {
            Some(auth_ctx) if auth_ctx.state.secret() == &expected_state => Ok(auth_ctx),
            Some(_) => Err(AuthError::CsrfMismatch),
            None => Err(AuthError::InvalidAuthState),
        }
    }
}

/// Holds intermediate values needed to complete the authorization flow.
///
/// These values are generated during the [authorize](CliOAuth::authorize) step, and
/// provided to the caller after [validation](CliOAuth::validate). They can then be used for the
/// [code exchange](oauth2::Client::exchange_code).
#[derive(Debug)]
pub struct AuthContext {
    /// The authorization code obtained from the Authorize step.
    pub auth_code: AuthorizationCode,
    pub state: CsrfToken,
    /// The PKCE verifier that will be supplied to the Exchange Code step.
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

/// Finds an available port within the give range.
///
/// Each port will be tried in ascending order. The first port that can successfully bind will be
/// used, and the resulting socket address will be returned. An error will be returned if no ports
/// in the range are available.
///
/// Note that this function **cannot guarantee** that the address/port combination will be usable by
/// the server, since any other process on the system could bind to it before this process does.
fn find_available_port(ip_addr: IpAddr, port_range: PortRange) -> ConfigResult<SocketAddr> {
    for port in port_range.clone() {
        let socket_addr = SocketAddr::new(ip_addr, port);
        if is_address_available(socket_addr) {
            return Ok(socket_addr);
        }
    }
    Err(CannotBindAddress {
        addr: ip_addr,
        port_range,
    })
}

/// Checks whether the given socket address is available for this process to use.
fn is_address_available(socket_addr: SocketAddr) -> bool {
    TcpListener::bind(socket_addr).is_ok()
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

    use rstest::{fixture, rstest};

    use crate::{find_available_port, is_address_available, PortRange};

    pub(crate) static LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    pub(crate) static PORT_GENERATOR: AtomicU16 = AtomicU16::new(8000);

    /// Acquires a range of port numbers for a test.
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

    /// Acquires a range of port numbers for a test.
    ///
    /// This is an alternative to [`next_ports`].
    pub(crate) fn port_range(count: u16) -> PortRange {
        let (start, end) = next_ports(count);
        start..end
    }

    #[fixture]
    fn one_port() -> PortRange {
        port_range(1)
    }

    #[fixture]
    fn two_ports() -> PortRange {
        port_range(2)
    }

    #[fixture]
    fn three_ports() -> PortRange {
        port_range(3)
    }

    #[rstest]
    fn find_available_port_with_open_port(three_ports: PortRange) {
        let res = find_available_port(LOCALHOST, three_ports.clone());
        match res {
            Ok(addr) => assert!(three_ports.contains(&addr.port())),
            Err(e) => panic!("error finding available port: {:?}", e),
        }
    }

    #[rstest]
    fn find_available_port_with_no_open_port(two_ports: PortRange) {
        // Acquire sockets on both ports we need
        let _s1 = TcpListener::bind(SocketAddr::new(LOCALHOST, two_ports.start)).unwrap();
        let _s2 = TcpListener::bind(SocketAddr::new(LOCALHOST, two_ports.end)).unwrap();
        let res = find_available_port(LOCALHOST, two_ports);
        res.expect_err("ports should not be available");
    }

    #[rstest]
    fn check_address_is_available_when_port_is_open(two_ports: PortRange) {
        let _sock = TcpListener::bind(SocketAddr::new(LOCALHOST, two_ports.end))
            .expect("control port {open_port} is already open");
        let address = SocketAddr::new(LOCALHOST, two_ports.start);
        assert!(is_address_available(address));
    }

    #[rstest]
    fn check_address_is_not_available_when_port_is_used(one_port: PortRange) {
        let _socket = TcpListener::bind(SocketAddr::new(LOCALHOST, one_port.end)).expect(
            "port is already \
            open",
        );
        let address = SocketAddr::new(LOCALHOST, one_port.start);
        assert!(!is_address_available(address));
    }

    mod cli_oauth {
        use crate::{AuthContext, AuthError, AuthorizationResult, CliOAuth};
        use oauth2::{AuthorizationCode, CsrfToken, PkceCodeVerifier};
        use rstest::{fixture, rstest};

        #[fixture]
        fn auth() -> CliOAuth {
            CliOAuth {
                address: ([127, 0, 0, 1], 8080).into(),
                timeout: 30,
                scopes: vec![],
                auth_context: None,
                auth_result: None,
            }
        }

        #[fixture]
        fn auth_context() -> AuthContext {
            AuthContext {
                state: CsrfToken::new(String::from("state")),
                auth_code: AuthorizationCode::new(String::from("code")),
                pkce_verifier: PkceCodeVerifier::new(String::from("pkce")),
            }
        }

        #[fixture]
        fn auth_result() -> AuthorizationResult {
            AuthorizationResult {
                auth_code: String::from("code"),
                state: String::from("state"),
            }
        }

        #[rstest]
        fn redirect_url_valid(auth: CliOAuth) {
            let url = auth.redirect_url();
            assert_eq!("http://127.0.0.1:8080/", url.as_str());
        }

        #[rstest]
        fn validate_with_no_context(mut auth: CliOAuth, auth_result: AuthorizationResult) {
            auth.auth_result = Some(auth_result);
            assert!(auth.validate().is_err());
        }

        #[rstest]
        fn validate_with_no_result(mut auth: CliOAuth, auth_context: AuthContext) {
            auth.auth_context = Some(auth_context);
            assert!(auth.validate().is_err());
        }

        #[rstest]
        fn validate_state_mismatch(
            mut auth: CliOAuth,
            mut auth_result: AuthorizationResult,
            auth_context: AuthContext,
        ) {
            auth_result.state = String::from("other_state");
            auth.auth_result = Some(auth_result);
            auth.auth_context = Some(auth_context);
            match auth.validate() {
                Err(AuthError::CsrfMismatch) => (),
                Err(e) => panic!("CsrfMismatch error should be raised, but was {:?}", e),
                Ok(_) => panic!("Validation should fail"),
            };
        }
    }
}
