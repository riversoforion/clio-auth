use log::{debug, error, info, warn};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use reqwest::header::{HeaderMap, AUTHORIZATION};
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use clio_auth::AuthContext;

#[tokio::main]
async fn main() {
    // Defaults to info. Set `RUST_LOG=debug` for verbose output.
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    debug!("😃 I'm alive");
    // Build helper
    // Only read-only scopes are requested: this example just fetches your profile and runs a
    // video search. If you adapt it to call APIs that modify data, add the scopes you need.
    let yt_readonly = Scope::new("https://www.googleapis.com/auth/youtube.readonly".to_string());
    let g_user_info = Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string());
    let mut auth = clio_auth::CliOAuth::builder()
        .timeout(30)
        .scope(g_user_info)
        .scope(yt_readonly)
        .build()
        .unwrap();
    // Configure OAuth struct
    //
    // NOTE: These are shared, intentionally public demo credentials. They live in a dedicated
    // GCP project that exists solely so you can run this example without creating your own
    // Google Cloud project and API credentials. The client is limited to read-only scopes and
    // the project's API quota is capped. Do not use these credentials for anything real —
    // register your own OAuth client for that.
    let client_id =
        "576721077498-7iacq9cpl4a5al4no0crbta6pet36t44.apps.googleusercontent.com".to_string();
    // Well, this sucks. Google doesn't support the PKCE flow without a client secret. Sort of
    // defeats the original purpose of PKCE, but whatever. Per RFC 8252 §8.4 (and Google's own
    // docs), a client secret embedded in a native/CLI app is not actually confidential — so
    // shipping it here leaks nothing that the architecture doesn't already assume is public.
    // Hopefully someday they'll relax the restriction, and then I can drop this.
    let client_secret = "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".to_string();
    let auth_url = "https://accounts.google.com/o/oauth2/v2/auth".to_string();
    let token_url = "https://oauth2.googleapis.com/token".to_string();
    let oauth_client = BasicClient::new(ClientId::new(client_id))
        .set_client_secret(ClientSecret::new(client_secret))
        .set_auth_uri(AuthUrl::new(auth_url).unwrap())
        .set_token_uri(TokenUrl::new(token_url).unwrap())
        .set_redirect_uri(auth.redirect_url());
    info!("🟢 starting...");
    match auth.authorize(&oauth_client).await {
        Ok(auth_url) => info!("✅ authorized successfully (url: {})", auth_url),
        Err(e) => warn!("⚠️ uh oh! {e:?}"),
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
                info!("🔑 token type: {:?}", token_result.token_type());
                info!("🔑 scopes: {:?}", token_result.scopes());

                let access_token = access_token.secret();
                match build_client(access_token) {
                    Ok(client) => {
                        info!("📞 Invoking Google/YouTube APIs...");
                        show_account_info(&client).await;
                        search_for_videos(&client).await;
                    }
                    Err(e) => error!("💀 error building HTTP client: {e:?}"),
                }
            } else {
                error!(
                    "💀 error exchanging auth code: {:?}",
                    token_result.unwrap_err()
                );
            }
        }
        Err(e) => warn!("⚠️ uh oh! {e:?}"),
    };
    info!("🏁 finished!");
}

fn build_client(access_token: &String) -> reqwest::Result<Client> {
    let mut headers = HeaderMap::with_capacity(1);
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {access_token}").parse().unwrap(),
    );
    Client::builder().default_headers(headers).build()
}

async fn show_account_info(client: &Client) {
    let mut url = "https://www.googleapis.com/oauth2/v2/userinfo"
        .parse::<Url>()
        .unwrap();
    url.query_pairs_mut().append_pair("alt", "json");
    match client.get(url).send().await {
        Ok(response) => match response.json::<UserInfo>().await {
            Ok(user) => {
                info!("🧍 User {}: {}", user.id, user.name);
                info!("📸 Avatar: {}", user.picture);
            }
            Err(e) => error!("💀 response parsing error: {e:?}"),
        },
        Err(e) => error!("💀 request error: {e:?}"),
    }
}

async fn search_for_videos(client: &Client) {
    let mut url = "https://www.googleapis.com/youtube/v3/search"
        .parse::<Url>()
        .unwrap();
    let mut query = url.query_pairs_mut();
    query.append_pair("maxResults", "5");
    query.append_pair("part", "snippet");
    query.append_pair("q", "never gonna give you up");
    drop(query);
    match client.get(url).send().await {
        Ok(response) => match response.json::<SearchResults>().await {
            Ok(result) => {
                result.items.into_iter().for_each(|result| {
                    info!(
                        "🎬 https://www.youtube.com/watch?v={}: {}",
                        result.id.video_id, result.snippet.title
                    )
                });
            }
            Err(e) => error!("💀 response parsing error: {e:?}"),
        },
        Err(e) => error!("💀 request error: {e:?}"),
    }
}

// Google/YouTube response types

#[derive(Deserialize, Debug)]
struct UserInfo {
    id: String,
    name: String,
    picture: String,
}

#[derive(Deserialize, Debug)]
struct SearchResults {
    items: Vec<SearchResult>,
}

#[derive(Deserialize, Debug)]
struct SearchResult {
    id: VideoId,
    snippet: Snippet,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VideoId {
    video_id: String,
}

#[derive(Deserialize, Debug)]
struct Snippet {
    title: String,
}
