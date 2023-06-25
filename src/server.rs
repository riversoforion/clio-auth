use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::error::ServerError;
use crate::AuthCodeHolder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use tokio::sync::mpsc;
use tokio::time;

#[derive(Debug)]
pub enum ServerControl {
    Shutdown,
}

pub(crate) async fn launch(
    address: SocketAddr,
    auth_code_holder: AuthCodeHolder,
    control_sender: mpsc::Sender<ServerControl>,
    control_receiver: mpsc::Receiver<ServerControl>,
    timeout: u64,
) {
    println!("🚀 launching http server...");
    // Create Hyper server
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
    println!("🏃 server running at http://{}", address);
    println!("⏳ waiting for {timeout} seconds");
    if let Err(e) = server.await {
        eprintln!("⚠️ server error: {}", e);
    }
}

async fn handle_request(
    request: Request<Body>,
    auth_code_holder: AuthCodeHolder,
    control_sender: mpsc::Sender<ServerControl>,
) -> Result<Response<Body>, ServerError> {
    // TODO Extract auth code from request
    let resp = match extract_auth_code(&request) {
        Some(code) => {
            println!("🎁 saving auth code {code}");
            // TODO Build "acknowledgment" body
            let body = Body::from(format!("{}\n", code.clone()));
            {
                let mut auth_code = auth_code_holder.lock().unwrap();
                *auth_code = Some(code);
            }
            println!("📤 sending shutdown signal");
            control_sender.send(ServerControl::Shutdown).await?;
            Response::builder()
                .header("Connection", "close")
                .body(body)
                .unwrap()
        },
        None => Response::builder()
            .status(400)
            .header("Connection", "close")
            .body(Body::from(
                "Query parameter 'myparam' is required".to_string(),
            ))
            .unwrap(),
    };
    Ok::<_, ServerError>(resp)
}

fn extract_auth_code(request: &Request<Body>) -> Option<String> {
    let params: HashMap<String, String> = query_params(&request);
    match params.get("myparam") {
        Some(myparam) => Some(myparam.chars().rev().collect()),
        None => None,
    }
}

fn query_params(request: &Request<Body>) -> HashMap<String, String> {
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

async fn shutdown_signal(mut control_receiver: mpsc::Receiver<ServerControl>, timeout: u64) {
    let timeout = time::timeout(Duration::from_secs(timeout), async {
        match control_receiver.recv().await {
            Some(_) => println!("📥 received shutdown signal"),
            None => println!("⬇️ channel was dropped"),
        };
    });
    let _ = timeout.await;
    println!("🛑 shutting down server...");
}
