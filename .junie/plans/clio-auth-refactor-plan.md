**Target Path:** /Users/ericmcintyre/Development/src/clio-auth/.junie/plans/clio-auth-refactor-plan.md Based on Sections 5, 6, and 7 of the caspian architecture
document, the primary goal for modifying clio-auth is to transition it from a one-shot CLI helper into a **sans-io reference engine** (clio-auth-core) and a
convenient high-level wrapper (clio-auth).

# **Architecture Modification Plan: clio-auth**

Refactor clio-auth to serve as the step-exposing, sans-io state machine reference engine required by caspian-core while maintaining backwards compatibility for
existing crate consumers.

## **1\. Plan Overview & Objectives**

* **Split Architecture**: Extract core state machine logic into clio-auth-core (no\_std / WASM safe) and leave loopback/I/O execution to clio-auth.
* **Step-Exposing State Machine**: Expose intermediate protocol stages (AuthorizationUrlReady, ExchangeRequestReady) so tools like caspian can inspect, step
  through, or modify OAuth steps.
* **Backwards Compatibility**: Keep the existing high-level CliOAuthBuilder and execution API working unchanged by delegating internally to the new state
  machine.
* **Trace-Ready Events**: Provide serializable data structures for protocol steps to feed into caspian’s TraceSink and FlowEvent models.

## **2\. Target Workspace Structure**

```text
clio-auth/
├── Cargo.toml                    # Workspace manifest
├── clio-auth-core/               # Sans-io state machine engine
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── state.rs              # FlowState enum & transition rules
│       ├── pkce.rs               # Code verifier/challenge logic
│       ├── request.rs            # HttpRequest/HttpResponse abstractions
│       └── error.rs              # Machine-readable FlowError types
└── clio-auth/                    # Existing crate (now I/O wrapper)
    ├── Cargo.toml                # Depends on clio-auth-core
    └── src/
        ├── lib.rs
        ├── driver.rs             # Tokio/Reqwest runtime driver
        └── server.rs             # Local loopback HTTP server
```

## **3\. Implementation Phases**

### **Phase 1: Core State Machine (clio-auth-core)**

1. **Define FlowState Enum**: Implement explicit, step-by-step state representations.
    ```rust
    pub enum FlowState {
       AuthorizationUrlReady { url: Url, pkce: PkceChallenge },
       AwaitingCallback { redirect_uri: Url },
       CallbackReceived { code: AuthCode, state_valid: bool },
       ExchangeRequestReady { request: HttpRequest }, // Step-Mode / Inspection anchor
       TokensReceived { response: TokenResponse },
       Failed { error: FlowError },
    }
    ```
2. **Implement Sans-I/O Engine**: Build a pure state transition struct AuthCodeEngine that consumes input events (CallbackParams, TokenResponse) and produces
   the next FlowState without executing network calls or opening browsers directly.
3. **Decouple HTTP Types**: Create lightweight, platform-agnostic HttpRequest and HttpResponse struct definitions.

### **Phase 2: Refactor clio-auth Driver**

1. **Re-implement High-Level API**: Update CliOAuth to use AuthCodeEngine under the hood.
2. **Loopback Server & Browser Launching**: Drive AwaitingCallback by spawning the local HTTP server, opening the browser, and feeding the callback back into
   the engine.
3. **Token Exchange Driver**: Take the ExchangeRequestReady state, execute the HTTP request via reqwest, and feed the HTTP response back to the core state
   machine.

### **Phase 3: Integration with Caspian Trace Model**

1. **Export Trace Data**: Ensure all state transitions output structured details (URL, headers, redacted body fields) compatible with caspian-core's FlowEvent.
2. **Step Mode Support**: Add a driver hook allowing callers to pause and mutate HttpRequest during the ExchangeRequestReady state.

## **4\. Verification & Testing Strategy**

| Test Area                           | Scope                  | Validation                                                                       |
|:------------------------------------|:-----------------------|:---------------------------------------------------------------------------------|
| **Unit Tests (clio-auth-core)**     | Pure state transitions | Test state transitions deterministically without network calls or local sockets. |
| **Compatibility Tests (clio-auth)** | API surface            | Verify existing tests and examples compile and execute without breaking changes. |
| **Integration Tests**               | Flow execution         | Run against a mock OAuth server and local Keycloak instance.                     |
