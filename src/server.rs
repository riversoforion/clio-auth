use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use log::{debug, error, info};
use poem::error::IntoResult;
use poem::http::StatusCode;
use poem::listener::TcpListener;
use poem::middleware::AddData;
use poem::web::{Data, Html, Query};
use poem::{get, handler, EndpointExt, Error, IntoResponse, Route, Server};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio::{select, signal};

use crate::error::ServerError;
use crate::ServerError::NoResult;
use crate::{AuthorizationResult, AuthorizationResultHolder};

pub(crate) async fn launch(
    address: SocketAddr,
    timeout: Duration,
) -> Result<AuthorizationResult, ServerError> {
    info!("🚀 launching http server...");

    // Create shared state
    let auth_code_holder = AuthorizationResultHolder::new(Mutex::new(None));
    // Create server control queue
    let (server_control_tx, server_control_rx) = mpsc::channel(1);

    // Create Poem application
    let app = Route::new()
        .at("", get(handle_request))
        .with(AddData::new(auth_code_holder.clone()))
        .with(AddData::new(server_control_tx))
        .catch_all_error(default_error_response);
    // Start server
    let server = Server::new(TcpListener::bind(address))
        .idle_timeout(timeout)
        .run_with_graceful_shutdown(
            app,
            server_control(server_control_rx, timeout),
            Some(timeout),
        );
    info!("🏃 server running at http://{address}");
    debug!("⏳ waiting for {timeout:?}");

    match server.await {
        Err(e) => {
            error!("⚠️ server error: {e}");
            Err(ServerError::InternalServerError(e))
        }
        Ok(()) => match &*auth_code_holder.lock().unwrap() {
            Some(auth_result) => Ok(auth_result.clone()),
            None => Err(NoResult),
        },
    }
}

#[handler]
async fn handle_request(
    query_params: Query<AuthCodeQueryParams>,
    auth_code_data: Data<&AuthorizationResultHolder>,
    control_sender_data: Data<&Sender<ServerControl>>,
) -> poem::Result<impl IntoResponse> {
    let auth_result = extract_auth_params(query_params.0)?;
    debug!("🎁 handling authorization result {auth_result:?}");
    // Artificial scope to unlock the mutex
    {
        let mut auth_code = auth_code_data.lock().unwrap();
        *auth_code = Some(auth_result);
    }
    let response = default_ok_response();
    debug!("✉️ sending shutdown signal");
    if let Err(send_error) = control_sender_data
        .send(ServerControl::Shutdown(
            "received authorization code".to_owned(),
        ))
        .await
    {
        Err(ServerError::from(send_error)).into_result()
    } else {
        response.into_result()
    }
}

fn extract_auth_params(params: AuthCodeQueryParams) -> poem::Result<AuthorizationResult> {
    match (params.code, params.state) {
        (Some(auth_code), Some(state)) => Ok(AuthorizationResult { auth_code, state }),
        _ => {
            error!("⚠️ missing authorization code query parameters");
            Err(NoResult.into())
        }
    }
}

fn default_ok_response() -> impl IntoResponse {
    let content = String::from(
        r"
    <html>
        <h1>Success!</h1>
        <p>You have successfully authenticated. You can close this window now.</p>
    </html>
    ",
    );
    Html(content)
        .with_status(StatusCode::OK)
        .with_header("Referrer-Policy", "no-referrer")
}

async fn default_error_response(error: Error) -> impl IntoResponse {
    let error_text = format!("{error}");
    let escaped_error = html_escape::encode_safe(&error_text);
    let content = format!(
        r"
    <html>
        <h1 style='color: red'>Error!</h1>
        <p>There was an error authenticating. Please try again.</p>
        <p>Details: {escaped_error}</p>
    </html>
    ",
    );
    Html(content)
        .with_status(error.status())
        .with_header("Referrer-Policy", "no-referrer")
}

#[cfg(not(tarpaulin_include))]
async fn server_control(mut control_receiver: mpsc::Receiver<ServerControl>, timeout: Duration) {
    select! {
        msg = control_receiver.recv() => {
            match msg {
                Some(_) => debug!("📨 received shutdown message"),
                None => debug!("⬇️ channel was dropped"),
            }
        },
        _ = sleep(timeout) => debug!("⌛️ server timed out"),
        _ = signal::ctrl_c() => debug!("🚦 received interrupt signal"),
    }
    info!("🛑 shutting down server...");
}

#[derive(Debug)]
pub enum ServerControl {
    Shutdown(String),
}

#[derive(Deserialize)]
struct AuthCodeQueryParams {
    code: Option<String>,
    state: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::server::{
        default_error_response, default_ok_response, extract_auth_params, launch,
        AuthCodeQueryParams,
    };
    use crate::ServerError;
    use poem::{Error, IntoResponse};
    use reqwest::StatusCode;
    use std::io;
    use std::io::ErrorKind;
    use std::mem::discriminant;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU16;
    use std::sync::atomic::Ordering::AcqRel;
    use std::time::Duration;

    static LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    static PORT_GENERATOR: AtomicU16 = AtomicU16::new(9000);

    fn next_port() -> u16 {
        PORT_GENERATOR.fetch_add(1, AcqRel)
    }

    #[tokio::test]
    async fn launch_handles_auth_callback() {
        let addr = SocketAddr::new(LOCALHOST, next_port());
        let server = tokio::spawn(launch(addr, Duration::from_secs(5)));
        // Give the server a moment to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://{}?code=test_code&state=test_state", addr))
            .await
            .expect("request should succeed");
        assert_eq!(resp.status(), StatusCode::OK);

        let result = server
            .await
            .expect("task should complete")
            .expect("server should return a result");
        assert_eq!(result.auth_code, "test_code");
        assert_eq!(result.state, "test_state");
    }

    #[tokio::test]
    async fn launch_times_out_with_no_request() {
        let addr = SocketAddr::new(LOCALHOST, next_port());
        let result = launch(addr, Duration::from_millis(100)).await;
        assert!(matches!(result, Err(ServerError::NoResult)));
    }

    #[tokio::test]
    async fn launch_returns_error_on_missing_code() {
        let addr = SocketAddr::new(LOCALHOST, next_port());
        let server = tokio::spawn(launch(addr, Duration::from_secs(5)));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Missing `code` param — server should respond with 400 and eventually time out
        let resp = reqwest::get(format!("http://{}?state=test_state", addr))
            .await
            .expect("request should succeed");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Server gets no valid code so it times out — abort to avoid waiting
        server.abort();
    }

    #[test]
    fn extract_auth_params_when_present() {
        let params = AuthCodeQueryParams {
            code: Some("auth_code".to_owned()),
            state: Some("auth_state".to_owned()),
        };
        let result = extract_auth_params(params);
        assert!(result.is_ok());
    }

    #[test]
    fn extract_auth_params_when_code_missing() {
        let params = AuthCodeQueryParams {
            code: None,
            state: Some("auth_state".to_owned()),
        };
        let result = extract_auth_params(params);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        let server_error = error.downcast::<ServerError>().unwrap();
        assert_eq!(
            discriminant(&server_error),
            discriminant(&ServerError::NoResult)
        );
    }

    #[test]
    fn extract_auth_params_when_state_missing() {
        let params = AuthCodeQueryParams {
            code: Some("auth_code".to_owned()),
            state: None,
        };
        let result = extract_auth_params(params);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        let server_error = error.downcast::<ServerError>().unwrap();
        assert_eq!(
            discriminant(&server_error),
            discriminant(&ServerError::NoResult)
        );
    }

    #[tokio::test]
    async fn default_ok_response_has_success_message() {
        let response = default_ok_response().into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let content = body.into_string().await.unwrap();
        assert!(content.contains("Success!"));
        assert!(content.contains("successfully authenticated"));
    }

    #[tokio::test]
    async fn default_ok_response_sets_referrer_policy() {
        let response = default_ok_response().into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers["referrer-policy"], "no-referrer");
    }

    #[tokio::test]
    async fn default_error_response_has_error_message() {
        let error = Error::new(
            ServerError::InternalServerError(io::Error::new(ErrorKind::AddrInUse, "the problem")),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        let response = default_error_response(error).await.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body();
        let content = body.into_string().await.unwrap();
        assert!(content.contains("Error!"));
        assert!(content.contains("Details: Internal server error"));
    }

    #[tokio::test]
    async fn default_error_response_escapes_html() {
        let xss_payload = "<script>alert('xss')</script>";
        let error = Error::from_string(xss_payload, StatusCode::BAD_REQUEST);
        let response = default_error_response(error).await.into_response();
        let body = response.into_body();
        let content = body.into_string().await.unwrap();

        assert!(
            !content.contains(xss_payload),
            "XSS payload should be escaped"
        );
        assert!(content.contains("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"));
    }

    #[tokio::test]
    async fn default_error_response_sets_referrer_policy() {
        let error = Error::new(
            ServerError::InternalServerError(io::Error::new(ErrorKind::AddrInUse, "the problem")),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        let response = default_error_response(error).await.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let headers = response.headers();
        assert_eq!(headers["referrer-policy"], "no-referrer");
    }
}
