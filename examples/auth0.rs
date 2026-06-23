use log::{debug, error, info, warn};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, TokenResponse, TokenUrl};

use clio_auth::AuthContext;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    debug!("😃 I'm alive");
    // Build helper
    let mut auth = clio_auth::CliOAuth::builder().timeout(30).build().unwrap();
    // Configure OAuth struct
    let client_id = "gc1p9v7obY6fuPFv6nDz8oSVoO6lX4Ia".to_string();
    let auth_url = "https://riversoforion.auth0.com/authorize".to_string();
    let token_url = "https://riversoforion.auth0.com/oauth/token".to_string();
    let oauth_client = BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(AuthUrl::new(auth_url).unwrap())
        .set_token_uri(TokenUrl::new(token_url).unwrap())
        .set_redirect_uri(auth.redirect_url());
    info!("🟢 starting...");
    match auth.authorize(&oauth_client).await {
        Ok(auth_url) => info!("✅ authorized successfully (url: {})", auth_url),
        Err(e) => warn!("⚠️ uh oh! {:?}", e),
    };
    match auth.validate() {
        Ok(AuthContext {
            auth_code,
            pkce_verifier,
            state: _,
        }) => {
            info!("✅ auth code is good to go");
            let http_client = oauth2::reqwest::Client::new();
            let token_result = oauth_client
                .exchange_code(auth_code)
                .set_pkce_verifier(pkce_verifier)
                .request_async(&http_client)
                .await;
            if let Ok(token_result) = token_result {
                let access_token = token_result.access_token();
                info!("🔑 access token:\n{}", access_token.secret());
                info!("🔑 token type: {:?}", token_result.token_type());

                let refresh_token = token_result.refresh_token();
                if let Some(refresh_token) = refresh_token {
                    info!("🔑 refresh token:\n{}", refresh_token.secret());
                } else {
                    info!("🔒 refresh token not returned");
                }
            } else {
                error!(
                    "💀 error exchanging auth code: {:?}",
                    token_result.unwrap_err()
                );
            }
        }
        Err(e) => warn!("⚠️ uh oh! {:?}", e),
    };
    info!("🏁 finished!");
}
