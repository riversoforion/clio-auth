use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body,
    body::{Body, Bytes},
    service::service_fn,
    Request, Response,
};
use log::{debug, error, info};
use tokio::sync::mpsc;
use tokio::time;

use crate::error::ServerError;
use crate::{AuthorizationResult, AuthorizationResultHolder};

#[derive(Debug)]
pub enum ServerControl {
    Shutdown,
}

#[cfg(not(tarpaulin_include))]
pub(crate) async fn launch(
    address: SocketAddr,
    auth_code_holder: AuthorizationResultHolder,
    control_sender: mpsc::Sender<ServerControl>,
    control_receiver: mpsc::Receiver<ServerControl>,
    timeout: u64,
) {
    info!("🚀 launching http server...");
    // Create Hyper server
    // Open socket
    // Start timer
    // Loop while waiting for a connection
    // Wait until we successfully received a token or the timeout passed
    //   This might be a job for a Tokio select! macro

    /*
    let service_factory = make_service_fn(move |_| {
        let control_sender = control_sender.to_owned();
        let auth_code_holder = Arc::clone(&auth_code_holder);
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(
                    req,
                    Arc::clone(&auth_code_holder),
                    control_sender.to_owned(),
                )
            }))
        }
    });
    let server = Server::bind(&address).serve(service_factory);
    // Configure graceful shutdown
    let server = server.with_graceful_shutdown(shutdown_signal(control_receiver, timeout));
    info!("🏃 server running at http://{}", address);
    debug!("⏳ waiting for {timeout} seconds");
    if let Err(e) = server.await {
        error!("⚠️ server error: {}", e);
    }
     */
}

#[cfg(not(tarpaulin_include))]
async fn handle_request(
    request: Request<body::Incoming>,
    auth_code_holder: AuthorizationResultHolder,
    control_sender: mpsc::Sender<ServerControl>,
) -> Result<Response<BoxBody<Bytes, ServerError>>, ServerError> {
    let resp = match extract_auth_params(&request) {
        Some(result) => {
            debug!("🎁 handling authorization result {result:?}");
            // Artificial scope to unlock the mutex
            {
                let mut auth_code = auth_code_holder.lock().unwrap();
                *auth_code = Some(result);
            }
            let body = build_ok_body();
            debug!("📤 sending shutdown signal");
            control_sender.send(ServerControl::Shutdown).await?;
            Response::builder()
                .header("Connection", "close")
                .body(body)
                .unwrap()
        }
        None => Response::builder()
            .status(400)
            .header("Connection", "close")
            .body(build_err_body("Authorization code or state not provided"))
            .unwrap(),
    };
    Ok::<_, ServerError>(resp)
}

fn extract_auth_params(request: &Request<impl Body>) -> Option<AuthorizationResult> {
    let params: HashMap<String, String> = query_params(request);
    let auth_code = match params.get("code") {
        Some(code) => code.to_owned(),
        None => return None,
    };
    let state = match params.get("state") {
        Some(state) => state.to_owned(),
        None => return None,
    };
    Some(AuthorizationResult { auth_code, state })
}

fn query_params(request: &Request<impl Body>) -> HashMap<String, String> {
    request
        .uri()
        .query()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_else(HashMap::new)
}

fn build_ok_body() -> BoxBody<Bytes, ServerError> {
    let content = String::from(
        r"
    <html>
        <h1>Success!</h1>
        <p>You have successfully authenticated. You can close this window now.</p>
    </html>
    ",
    );
    Full::new(Bytes::from(content))
        .map_err(|never| match never {})
        .boxed()
}

fn build_err_body(details: &str) -> BoxBody<Bytes, ServerError> {
    let content = format!(
        r"
    <html>
        <h1 style='color: red'>Error!</h1>
        <p>There was an error authenticating. Please try again.</p>
        <p>Details: {details}</p>
    </html>
    ",
    );
    Full::new(Bytes::from(content))
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(not(tarpaulin_include))]
async fn shutdown_signal(mut control_receiver: mpsc::Receiver<ServerControl>, timeout: u64) {
    let timeout = time::timeout(Duration::from_secs(timeout), async {
        match control_receiver.recv().await {
            Some(_) => debug!("📥 received shutdown signal"),
            None => debug!("⬇️ channel was dropped"),
        };
    });
    let _ = timeout.await;
    info!("🛑 shutting down server...");
}

#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt, Empty};
    use hyper::{body::Bytes, Request, Uri};

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
}
