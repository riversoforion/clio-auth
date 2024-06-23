use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use log::{debug, error, info};
use poem::error::IntoResult;
use poem::http::StatusCode;
use poem::listener::TcpListener;
use poem::middleware::AddData;
use poem::web::{Data, Html, Query};
use poem::{get, handler, EndpointExt, IntoResponse, Route, Server};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio::{select, signal};

use crate::error::ServerError;
use crate::ServerError::NoResult;
use crate::{AuthorizationResult, AuthorizationResultHolder};

#[cfg(not(tarpaulin_include))]
pub(crate) async fn launch(
    address: SocketAddr,
    timeout: u64,
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
        .with(AddData::new(server_control_tx));
    // Start server
    let timeout = Duration::from_secs(timeout);
    let server = Server::new(TcpListener::bind(address))
        .idle_timeout(timeout)
        .run_with_graceful_shutdown(
            app,
            server_control(server_control_rx, timeout),
            Some(timeout),
        );
    info!("🏃 server running at http://{}", address);
    debug!("⏳ waiting for {timeout:?}");

    if let Err(e) = server.await {
        error!("⚠️ server error: {}", e);
        Err(ServerError::InternalServerError(e))
    } else {
        let AuthorizationResult {
            auth_code,
            state: state_in,
        } = match &mut *auth_code_holder.lock().unwrap() {
            Some(auth_result) => auth_result.clone(),
            None => return Err(NoResult),
        };
        Ok(AuthorizationResult {
            auth_code: auth_code.clone(),
            state: state_in.clone(),
        })
    }
}

#[cfg(not(tarpaulin_include))]
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
    let body = build_ok_body();
    debug!("✉️ sending shutdown signal");
    if let Err(send_error) = control_sender_data
        .send(ServerControl::Shutdown(
            "received authorization code".to_owned(),
        ))
        .await
    {
        Err(ServerError::from(send_error)).into_result()
    } else {
        body.into_result()
    }
}

fn extract_auth_params(params: AuthCodeQueryParams) -> poem::Result<AuthorizationResult> {
    if params.code.is_none() || params.state.is_none() {
        error!("⚠️ missing authorization code query parameters");
        Err(NoResult.into())
    } else {
        Ok(AuthorizationResult {
            auth_code: params.code.unwrap(),
            state: params.state.unwrap(),
        })
    }
}

fn build_ok_body() -> impl IntoResponse {
    let content = String::from(
        r"
    <html>
        <h1>Success!</h1>
        <p>You have successfully authenticated. You can close this window now.</p>
    </html>
    ",
    );
    Html(content).with_status(StatusCode::OK)
}

fn build_err_body(details: &str) -> impl IntoResponse {
    let content = format!(
        r"
    <html>
        <h1 style='color: red'>Error!</h1>
        <p>There was an error authenticating. Please try again.</p>
        <p>Details: {details}</p>
    </html>
    ",
    );
    Html(content).with_status(StatusCode::UNAUTHORIZED)
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
    /*
    use crate::server::{build_err_body, build_ok_body, extract_auth_params};

    #[test]
    fn extract_auth_params_valid() {
        let req = Request::builder()
            .uri(Uri::from_static(
                "https://auth.example.com/authorize?code=abcdef&state=12345&other=whatever",
            ))
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(extract_auth_params(&req).is_some());
    }

    #[test]
    fn extract_auth_params_missing_code() {
        let req = Request::builder()
            .uri(Uri::from_static(
                "https://auth.example.com/authorize?state=12345&other=whatever",
            ))
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(extract_auth_params(&req).is_none());
    }

    #[test]
    fn extract_auth_params_missing_state() {
        let req = Request::builder()
            .uri(Uri::from_static(
                "https://auth.example.com/authorize?code=abcdef&other=whatever",
            ))
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(extract_auth_params(&req).is_none());
    }

    #[tokio::test]
    async fn build_ok_body_has_success_message() {
        let body = build_ok_body();
        let content = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(content.contains("Success!"));
        assert!(content.contains("successfully authenticated"));
    }

    #[tokio::test]
    async fn build_err_body_has_error_message() {
        let body = build_err_body("the problem");
        let content = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(content.contains("Error!"));
        assert!(content.contains("Details: the problem"));
    }
     */
}
