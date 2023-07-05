# CliOAuth

CliOAuth (pronounced _"klee-oh-awth"_) is a utility to assist CLI/desktop application developers with implementing the 
OAuth 2.0 [Authorization Code flow with PKCE][1].

> _To learn more about Auth Code w/ PKCE, Auth0 has a [good tutorial][2]._

The [`oauth2`][3] crate provides an excellent OAuth2 client implementation. However, to support the Auth Code with PKCE
flow in a native desktop application, a couple of additional pieces are necessary:

- Launching a local web server to listen for the "authorization code" request
- Launching a browser with the "authorization" link
- Validating the CSRF token (i.e. the `state` parameter)

CliOAuth provides these pieces in an asynchronous and extensible way. It is designed to supplement the `oauth2::Client`
struct, but not interfere with its normal usage.

## Status

- [x] Launch an asynchronous web server to handle the auth code request
  - [x] Bind the server to any local address and non-privileged port
  - [x] Scan for a range of ports to find the first open one
- [x] Open the user's browser to begin the authorization flow
- [x] Validate the authorization result and make it available for a code exchange
- [ ] Customize the server responses in the browser
  - [ ] Successful authorization
  - [ ] Authorization error

[1]: https://www.rfc-editor.org/rfc/rfc7636
[2]: https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce
[3]: https://crates.io/crates/oauth2

## Usage

_TODO_
