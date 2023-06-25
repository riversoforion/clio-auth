use log::{debug, info, warn};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, TokenUrl};

#[tokio::main]
async fn main() -> Result<(), String> {
    pretty_env_logger::init();

    // TODO Cleanup output
    debug!("😃 I'm alive");
    // Configure OAuth struct
    let client_id = "gc1p9v7obY6fuPFv6nDz8oSVoO6lX4Ia";
    let auth_url = "https://riversoforion.auth0.com/authorize";
    let token_url = "https://riversoforion.auth0.com/oauth/token";
    let oauth_client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        None,
        AuthUrl::new(auth_url.to_string()).unwrap(),
        Some(TokenUrl::new(token_url.to_string()).unwrap()),
    );
    let mut auth = clio_auth::CliOAuth::builder(oauth_client)
        .timeout(30)
        .build()
        .unwrap();
    info!("🟢 starting...");
    match auth.fetch_auth_code().await {
        Ok(()) => info!("👍 good to go"),
        Err(e) => warn!("👎 uh oh! {:?}", e),
    };
    info!("🏁 finished!");
    Ok(())
}
