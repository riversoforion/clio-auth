# CliOAuth

[![GitHub Repository][gh-badge]][gh-url]
[![GitHub Build Status][gh-build-badge]][gh-build-url]
[![Crates.io][crates-badge]][crates-url]
[![docs.rs][docs-badge]][docs-url]

[gh-badge]: https://img.shields.io/badge/github-riversoforion%2Fclio--auth-23657d?style=for-the-badge&logo=github
[gh-url]: https://github.com/riversoforion/clio-auth
[gh-build-badge]: https://img.shields.io/github/actions/workflow/status/riversoforion/clio-auth/build-and-test.yaml?style=for-the-badge&logo=github
[gh-build-url]: https://github.com/riversoforion/clio-auth/actions/workflows/build-and-test.yaml
[crates-badge]: https://img.shields.io/crates/l/clio-auth?style=for-the-badge&logo=rust&color=gold
[crates-url]: https://crates.io/crates/clio-auth
[docs-badge]: https://img.shields.io/docsrs/clio-auth?style=for-the-badge&logo=docsdotrs&link=https%3A%2F%2Fdocs.rs%2Fclio-auth
[docs-url]: https://docs.rs/clio-auth/latest/clio_auth/

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

General usage is as follows:

1. Configure a `CliOAuthBuilder` to build a `CliOAuth` helper
2. Configure an `oauth2::Client`
3. Start the authorization flow
4. Validate and obtain the authorization code
5. Exchange the code for a token

See the [Crate documentation][crates-url] for more details, including an example.
