# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased]

## [0.9.0] - 2026-06-22

### Added
- VS Code extension recommendations, launch configs, tasks, and settings
- `CLAUDE.md` project documentation for Claude Code
- Automated release pipeline via `release-plz` (draft releases on merge, crates.io publish on release)
- `CHANGELOG.md` with full history back to v0.5.0
- Branch ruleset replacing classic branch protection, with correct check names

### Changed
- Dependency updates: tokio 1.52, reqwest 0.13, thiserror 2.0, and more
- Replaced `tokio` `full` feature flag with specific features used by the library
- Workflow improvements: Rust caching, prebuilt tarpaulin, concurrency groups, least-privilege permissions
- Bumped all GitHub Actions to latest major versions (checkout v7, codecov v7, upload-artifact v7)

### Fixed
- GitHub Actions `PR Verification` workflow was silently skipping the `build and test` job due to an invalid `if:` condition
- `youtube` example incompatibility with reqwest 0.13 API (`.query()` method removed from `RequestBuilder`)
- Clippy warnings: `unnecessary_unwrap` in server module, `doc_lazy_continuation` in lib docs
- Empty error message on `ServerError::InternalRuntimeError`
- Crate-level doctest was gated behind an always-false `#[cfg(feature = "reqwest")]` and never compiled

## [0.8.1] - 2024-06-26

### Fixed
- Build badge reference in README
- Release workflow token configuration

## [0.8.0] - 2024-06-26

### Changed
- Replaced Hyper directly with [Poem](https://github.com/poem-web/poem) as the local HTTP server framework

### Added
- Unit tests for server module request/response cycle
- Unit tests for error module
- Improved error handling with typed error hierarchy

### Fixed
- Timeout value is now passed as `Duration` rather than raw seconds throughout the stack

## [0.7.1] - 2024-05-15

### Fixed
- Deprecated GitHub Actions runner images updated
- Dependency versions updated per lib.rs compatibility recommendations

## [0.7.0] - 2023-08-27

Internal version bump.

## [0.6.0] - 2023-08-27

### Added
- Google/YouTube example demonstrating a real OAuth 2.0 flow
- Badge links in documentation

### Changed
- Documentation cleanup and improvements across the public API surface

## [0.5.0] - 2023-07-24

Initial release.

### Added
- `CliOAuth` struct and `CliOAuthBuilder` fluent builder
- Local HTTP server for OAuth 2.0 authorization code callback (built on Hyper)
- PKCE (Proof Key for Code Exchange) challenge/verifier generation
- CSRF state token generation and validation
- Automatic browser launch via the `open` crate
- Scope configuration support
- Structured error hierarchy: `ConfigError`, `ServerError`, `AuthError`
- Full Rustdoc on the public API surface
- Auth0 example
- CI pipeline with multi-platform builds and code coverage

<!-- next-url -->
[Unreleased]: https://github.com/riversoforion/clio-auth/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/riversoforion/clio-auth/compare/v0.8.0...v0.9.0
[0.8.1]: https://github.com/riversoforion/clio-auth/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/riversoforion/clio-auth/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/riversoforion/clio-auth/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/riversoforion/clio-auth/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/riversoforion/clio-auth/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/riversoforion/clio-auth/releases/tag/v0.5.0
