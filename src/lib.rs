//! Hive Router plugin that ports the `@labdigital/federated-token` gateway
//! behaviour (previously an Apollo Server plugin) to the Rust Hive Router.
//!
//! The subgraphs are unchanged: they keep speaking the `@labdigital/federated-token`
//! subgraph wire format (base64-JSON in `x-access-token` / `x-refresh-token`
//! HTTP headers). This crate reproduces that wire format byte-for-byte so the
//! gateway swap is transparent to every subgraph.
//!
//! Hook mapping (Apollo -> Hive Router):
//!   requestDidStart        -> on_graphql_params          (read + validate client tokens)
//!   datasource.willSendReq -> on_subgraph_execute        (inject tokens to subgraphs)
//!   datasource.didReceive  -> on_subgraph_http_request   (read minted tokens back)
//!   willSendResponse       -> on_http_request (.on_end)  (set cookies on the client)

pub mod config;
pub mod cookies;
pub mod errors;
pub mod plugin;
pub mod signer;
pub mod token;
