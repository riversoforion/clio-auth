use log::{debug, info, warn};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, TokenUrl};

#[tokio::main]
async fn main() -> Result<(), String> {
    pretty_env_logger::init();

    debug!("😃 I'm alive");
    // Build helper
    let mut auth = clio_auth::CliOAuth::builder().timeout(30).build().unwrap();
    // Configure OAuth struct
    let client_id = "gc1p9v7obY6fuPFv6nDz8oSVoO6lX4Ia";
    let auth_url = "https://riversoforion.auth0.com/authorize";
    let token_url = "https://riversoforion.auth0.com/oauth/token";
    let oauth_client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        None,
        AuthUrl::new(auth_url.to_string()).unwrap(),
        Some(TokenUrl::new(token_url.to_string()).unwrap()),
    )
    .set_redirect_uri(auth.redirect_url());
    info!("🟢 starting...");
    match auth.authorize(&oauth_client).await {
        Ok(()) => info!("👍 authorized successfully"),
        Err(e) => warn!("👎 uh oh! {:?}", e),
    };
    match auth.validate() {
        Ok(_auth_ctx) => info!("👍 auth code is good to go"),
        Err(e) => warn!("👎 uh oh! {:?}", e),
    }
    // TODO Exchange auth code for token
    info!("🏁 finished!");
    Ok(())
}
