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

## Architecture

The library exposes two main public types:

- **`CliOAuth`** ([src/lib.rs](src/lib.rs)) — top-level struct representing a configured OAuth session. Key methods: `authorize()` (starts the browser flow and local server) and `validate()` (verifies CSRF state and returns the auth code + PKCE verifier for token exchange).
- **`CliOAuthBuilder`** ([src/builder.rs](src/builder.rs)) — fluent builder for configuring `CliOAuth` (port/port range, IP address, timeout, scopes).

Supporting modules:

- **`server`** ([src/server.rs](src/server.rs)) — async HTTP server built on `poem`. Handles the OAuth redirect, extracts `code`/`state` query params, and signals shutdown. Uses a `Mutex`-backed shared state and `select!` for timeout/shutdown coordination.
- **`error`** ([src/error.rs](src/error.rs)) — typed error hierarchy: `ConfigError`, `ServerError`, `AuthError`.

### Authorization flow

1. `authorize()` generates a PKCE pair and state token, spawns the local server, and opens the browser.
2. The server receives the redirect, stores the auth params, and shuts down.
3. `validate()` checks the CSRF state and returns `AuthContext` (auth code + PKCE verifier).
4. The caller exchanges the code for a token using the `oauth2` crate.

### Port handling

`find_available_port()` and `is_address_available()` in `lib.rs` use an atomic counter for sequential port scanning, which keeps parallel tests from colliding on the same port.

### Testing

Tests use `rstest` for parameterized cases. Integration-style tests in `server.rs` exercise the full request/response cycle. The `mockall` crate is available for mocking.
