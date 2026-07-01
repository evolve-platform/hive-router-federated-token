# hive-router-federated-token

A [Hive Router](https://the-guild.dev/graphql/hive/docs/router) plugin (Rust)
that ports the `@labdigital/federated-token` **gateway** behaviour off Apollo
Server, so a Hive Router can replace an Apollo Federation gateway without
touching any subgraph.

Distributed as a standalone library crate so multiple router binaries can
depend on it and just register the plugin — the Hive Router plugin model is
"bring your own binary" (plugins are compiled in; there is no dynamic loading).

## Usage

Add it to your custom router binary and register the plugin:

```toml
# Cargo.toml — the hive-router version MUST match this crate's
[dependencies]
hive-router = { git = "https://github.com/graphql-hive/router", tag = "hive-router/v0.0.77" }
hive-router-federated-token = { git = "https://github.com/evolve-platform/hive-router-federated-token", tag = "v0.1.0" }
```

```rust
// src/main.rs
use hive_router::{
    configure_global_allocator, error::RouterInitError, init_rustls_crypto_provider, ntex,
    router_entrypoint, PluginRegistry, RouterGlobalAllocator,
};

configure_global_allocator!();

#[hive_router::main]
async fn main() -> Result<(), RouterInitError> {
    init_rustls_crypto_provider();
    router_entrypoint(
        PluginRegistry::new()
            .register::<hive_router_federated_token::plugin::FederatedTokenPlugin>(),
    )
    .await
}
```

```yaml
# router.config.yaml
plugins:
  federated_token:
    enabled: true
    config:
      issuer: ${JWT_ISSUER}
      audience: ${JWT_AUDIENCE}
      cookie_domain: ${COOKIE_DOMAIN}
      secure: true
      same_site: lax
      refresh_token_path: /graphql/auth
      encrypt_keys: [{ id: "1", secret: ${FEDERATED_TOKEN_ENCRYPT_KEY_1} }]
      sign_keys:    [{ id: "1", secret: ${FEDERATED_TOKEN_SIGN_KEY_1} }]
```

Note: Hive Router does not interpolate `${VAR}` in config, so this plugin expands
`${VAR}` in its own string fields at init (`PluginConfig::resolve_env`). Keep
secrets in the environment; each key secret must be 32 bytes (A256GCM / HS256).

## What it does

| `@labdigital/federated-token` (Apollo)      | Hive Router hook                       |
| ------------------------------------------- | ------------------------------------- |
| `GatewayAuthPlugin.requestDidStart`         | `on_graphql_params`                    |
| `FederatedGraphQLDataSource.willSendRequest` | `on_subgraph_execute`                |
| `FederatedGraphQLDataSource.didReceiveResponse` | `on_subgraph_http_request` (`.on_end`) |
| `GatewayAuthPlugin.willSendResponse`        | `on_http_request` (`.on_end` → `map_response`) |

Reproduces the token wire formats byte-for-byte (JWE `dir`+`A256GCM` access &
refresh, JWS `HS256` data token; base64-JSON `x-access-token`/`x-refresh-token`
between gateway and subgraphs), and the cookie set (`userToken`/`guestToken`,
`userData`/`guestData`, `refreshToken`, `userRefreshTokenExists`/
`guestRefreshTokenExists`) with the user/guest split by `isAuthenticated`.

## Build & test

```bash
cargo build
cargo test
```
