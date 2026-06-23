# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CliOAuth ("klee-oh-awth") is a Rust library implementing the OAuth 2.0 Authorization Code flow with PKCE for CLI and desktop applications. It provides the pieces the `oauth2` crate lacks: a local web server for authorization callbacks, browser launching, and CSRF token validation.

## Commands

```sh
# Build
cargo build

# Test (all tests)
cargo test

# Run a single test
cargo test <test_name>

# Lint
cargo clippy --all-targets --all-features

# Format check
cargo fmt --check --verbose

# Code coverage
cargo tarpaulin --out XML

# Run examples
cargo run --example auth0
cargo run --example youtube
```

Pre-commit hooks enforce `cargo fmt` and `cargo check`. Commit messages must follow Conventional Commits (build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test).

## Git

- **Never commit `Cargo.lock`** — it is listed in `.gitignore` and must stay out of version control. Do not pass it to `git add`.
- Work on a feature branch; do not commit directly to `main`.
- Branch naming convention follows the pattern used in the repo (e.g. `release/1.0`, `feat/some-feature`).

## Architecture

The library exposes two main public types:

- **`CliOAuth`** ([src/lib.rs](src/lib.rs)) — top-level struct representing a configured OAuth session. Key methods: `authorize()` (starts the browser flow and local server; returns `Result<Url, ServerError>`) and `validate()` (verifies CSRF state and returns the auth code + PKCE verifier for token exchange).
- **`CliOAuthBuilder`** ([src/builder.rs](src/builder.rs)) — fluent builder for configuring `CliOAuth` (port/port range, IP address, timeout, scopes, open_browser).

Supporting modules:

- **`server`** ([src/server.rs](src/server.rs)) — async HTTP server built on `poem`. Handles the OAuth redirect, extracts `code`/`state` query params, and signals shutdown. Uses a `Mutex`-backed shared state and `select!` for timeout/shutdown coordination.
- **`error`** ([src/error.rs](src/error.rs)) — typed error hierarchy: `ConfigError`, `ServerError`, `AuthError`.

### Authorization flow

1. `authorize()` generates a PKCE pair and state token, spawns the local server, and (by default) opens the browser.
2. The server receives the redirect, stores the auth params, and shuts down.
3. `authorize()` returns the authorization `Url` to the caller.
4. `validate()` checks the CSRF state and returns `AuthContext` (auth code + PKCE verifier).
5. The caller exchanges the code for a token using the `oauth2` crate.

The `CliOAuthBuilder::open_browser(bool)` option (default `true`) controls whether `authorize()` auto-opens the browser. When `false`, the URL is returned but the browser is not touched — useful in scripted or non-interactive contexts.

### Port handling

`find_available_port()` and `is_address_available()` in `lib.rs` use an atomic counter for sequential port scanning, which keeps parallel tests from colliding on the same port.

### Testing

Tests use `rstest` for parameterized cases. Integration tests in `server.rs` exercise the full request/response cycle by spinning up a real server and sending HTTP requests via `reqwest`. The `mockall` crate is available for mocking.

Port ranges in tests: `lib.rs` tests start at 8000 via `PORT_GENERATOR`; `server.rs` tests start at 9000 via their own `PORT_GENERATOR`. If you add tests that need ports, use the `next_ports` / `next_port` helpers in the respective module to get a unique range and avoid collisions.

## Dependencies

### oauth2 (v5)

oauth2 v5 introduced breaking changes from v4:

- `Client` generic parameters changed: `TT` (TokenType) was removed as a standalone param (now an associated type on `TR: TokenResponse`). `Client` now has 5 required params (`TE, TR, TIR, RT, TRE`) plus 5 `EndpointState` params with defaults (`HasAuthUrl`, `HasDeviceAuthUrl`, etc.).
- `authorize()` in this library requires `HasAuthUrl = EndpointSet` — callers must call `.set_auth_uri()` on the client before passing it in.
- `BasicClient::new()` now takes only `ClientId`. Use the builder methods `.set_auth_uri()`, `.set_token_uri()`, `.set_client_secret()`, `.set_redirect_uri()` to configure the client.
- For token exchange, use `oauth2::reqwest::Client` (re-exported from the `oauth2` crate) rather than a separately-versioned `reqwest::Client`. The dependency graph contains both `reqwest 0.12` (used by oauth2) and `reqwest 0.13` (dev-dependency for tests); using the wrong one causes a trait-not-satisfied compile error.

### reqwest

Two versions coexist in the dependency graph:

- `reqwest 0.12` — pulled in transitively by `oauth2`. Use `oauth2::reqwest::Client` in examples and library code that calls `request_async`.
- `reqwest 0.13` — direct dev-dependency, used in tests (e.g. `reqwest::get(...)` in server integration tests). This is fine because tests only make plain HTTP requests, not oauth2 token exchanges.
