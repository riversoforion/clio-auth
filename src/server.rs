use std::convert::Infallible;
use std::net::SocketAddr;
use std::thread;

use crate::server::ServerControl::Shutdown;
use crate::server::ServerError::StartupFailed;
use crossbeam::channel::{bounded, Receiver, Sender};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use oauth2::{TokenResponse, TokenType};
use thiserror::Error;

// TODO thiserror
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("server startup failed")]
    StartupFailed,
}

pub type ServerResult<T> = Result<T, ServerError>;

#[derive(Debug)]
pub(crate) struct AuthServer {
    result_receiver: Receiver<ServerResult<String>>,
    control_sender: Sender<ServerControl>,
}

impl AuthServer {
    pub(crate) async fn start(addr: SocketAddr) -> ServerResult<AuthServer> {
        // Create channel for receiving results (token or error)
        // Create channel for shutting down server
        // Spawn thread with Hyper web server
        //  - Receiver: shutdown channel
        //  - Sender: results channel
        // Spawn thread to wait for results or timeout
        //  - Receiver: results channel
        //  - Sender: shutdown channel
        //  - After result or timeout, send shutdown signal
        // Save token result into AuthServer struct
        let (result_snd, result_rcv) = bounded(1);
        let (ctrl_snd, ctrl_rcv) = bounded(1);
        let context = AppContext {
            result_sender: result_snd,
        };

        let make_svc = make_service_fn(move |_conn: &AddrStream| {
            let context = context.clone();
            let service = service_fn(move |req| AuthServer::handle_request(context.clone(), req));
            async move { Ok::<_, Infallible>(service) }
        });
        let server = Server::bind(&addr).serve(make_svc);
        let graceful = server.with_graceful_shutdown(AuthServer::shutdown_signal(ctrl_rcv));

        if let Err(e) = graceful.await {
            eprintln!("server error: {}", e);
            Err(StartupFailed)
        } else {
            Ok(AuthServer {
                result_receiver: result_rcv,
                control_sender: ctrl_snd,
            })
        }
    }

    async fn handle_request(
        context: AppContext<String>,
        req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        Ok(Response::new(Body::from("Handling request")))
    }

    async fn shutdown_signal(control_receiver: Receiver<ServerControl>) {
        let srv_ctl = async {
            loop {
                match control_receiver.recv() {
                    Ok(Shutdown) => break,
                    _ => continue,
                }
            }
        };
        // TODO implement a timeout
        // TODO Wait for both futures
        srv_ctl.await;
        println!("shutting down auth code server");
    }

    pub(crate) async fn get_tokens(&self) -> ServerResult<String> {
        match self.result_receiver.recv() {
            Ok(result) => result,
            // TODO thiserror to translate RecvError
            Err(error) => panic!("oh noes!"),
        }
    }

    pub(crate) fn shutdown(&mut self) -> ServerResult<()> {
        Ok(())
    }
}

impl Drop for AuthServer {
    fn drop(&mut self) {
        todo!("Shutdown the server")
    }
}

#[derive(Clone, Debug)]
struct AppContext<T> {
    result_sender: Sender<ServerResult<T>>,
}

#[derive(Debug)]
enum ServerControl {
    Shutdown,
}
