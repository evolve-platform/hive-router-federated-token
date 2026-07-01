use std::sync::Mutex;

use hive_router::async_trait;
use hive_router::http::header::{HeaderName, HeaderValue};
use hive_router::ntex::http::header::{HeaderValue as CookieHeaderValue, SET_COOKIE};
use hive_router::ntex::http::HeaderMap;
use hive_router::plugins::{
    hooks::{
        on_graphql_params::{OnGraphQLParamsStartHookPayload, OnGraphQLParamsStartHookResult},
        on_http_request::{OnHttpRequestHookPayload, OnHttpRequestHookResult},
        on_plugin_init::{OnPluginInitPayload, OnPluginInitResult},
        on_subgraph_execute::{
            OnSubgraphExecuteStartHookPayload, OnSubgraphExecuteStartHookResult,
        },
        on_subgraph_http_request::{
            OnSubgraphHttpRequestHookPayload, OnSubgraphHttpRequestHookResult,
        },
    },
    plugin_trait::{EndHookPayload, RouterPlugin, StartHookPayload},
};

use crate::config::PluginConfig;
use crate::cookies::{
    build_set_cookie, deletion, parse_cookies, CookieSpec, GUEST_DATA, GUEST_REFRESH_EXISTS,
    GUEST_TOKEN, REFRESH_TOKEN, USER_DATA, USER_REFRESH_EXISTS, USER_TOKEN,
};
use crate::errors::TokenError;
use crate::signer::TokenSigner;
use crate::token::FederatedToken;

/// Per-request token state shared across hooks via the plugin context.
///
/// Subgraph responses are merged concurrently (each subgraph HTTP call fires its
/// own `on_subgraph_http_request` end hook), so the token lives behind a Mutex.
/// The Node implementation gets this serialization for free from the single
/// threaded event loop.
struct TokenState {
    token: Mutex<FederatedToken>,
}

pub struct FederatedTokenPlugin {
    signer: TokenSigner,
    config: PluginConfig,
}

#[async_trait]
impl RouterPlugin for FederatedTokenPlugin {
    type Config = PluginConfig;

    fn plugin_name() -> &'static str {
        "federated_token"
    }

    fn on_plugin_init(payload: OnPluginInitPayload<Self>) -> OnPluginInitResult<Self> {
        let mut config = payload.config()?;
        // Hive Router doesn't interpolate `${VAR}` in config, so do it ourselves
        // (issuer/audience/cookie_domain/key secrets all come from the env).
        config.resolve_env();
        let signer = TokenSigner::from_config(&config)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        payload.initialize_plugin(FederatedTokenPlugin { signer, config })
    }

    /// Read + validate the client's tokens and stash them in the context.
    /// Runs on GraphQL requests only, so auth failures surface as GraphQL errors.
    async fn on_graphql_params<'exec>(
        &'exec self,
        payload: OnGraphQLParamsStartHookPayload<'exec>,
    ) -> OnGraphQLParamsStartHookResult<'exec> {
        let headers = payload.router_http_request.headers;
        let cookies = parse_cookies(headers);

        let mut token = FederatedToken::new();

        // Access token: authenticated cookie, then guest cookie, then header.
        let access = cookies
            .get(USER_TOKEN)
            .cloned()
            .or_else(|| cookies.get(GUEST_TOKEN).cloned())
            .or_else(|| header_str(headers, "x-access-token").map(strip_bearer));
        if let Some(access) = access {
            match self.signer.decrypt_access(&access) {
                Ok((tokens, is_authenticated)) => {
                    token.tokens = tokens;
                    token.is_authenticated = is_authenticated;
                }
                Err(e) => return payload.end_with_graphql_error(e.graphql_error(), e.status_code()),
            }
        }

        // Refresh token: cookie, then header.
        let refresh = cookies
            .get(REFRESH_TOKEN)
            .cloned()
            .or_else(|| header_str(headers, "x-refresh-token"));
        if let Some(refresh) = refresh {
            match self.signer.decrypt_refresh(&refresh) {
                Ok(refresh_tokens) => token.refresh_tokens = refresh_tokens,
                // The Apollo gateway always surfaced refresh failures as
                // INVALID_TOKEN / 400 regardless of the underlying cause.
                Err(_) => {
                    let e = TokenError::Invalid("invalid refresh token".into());
                    return payload.end_with_graphql_error(e.graphql_error(), e.status_code());
                }
            }
        }

        // Data token: authenticated cookie, then guest cookie, then header.
        let data = cookies
            .get(USER_DATA)
            .cloned()
            .or_else(|| cookies.get(GUEST_DATA).cloned())
            .or_else(|| header_str(headers, "x-data-token"));
        if let Some(data) = data {
            match self.signer.verify_data(&data) {
                Ok(values) => token.values = values,
                Err(e) => return payload.end_with_graphql_error(e.graphql_error(), e.status_code()),
            }
        }

        payload.context.insert(TokenState {
            token: Mutex::new(token),
        });
        payload.proceed()
    }

    /// Inject the serialized token onto every outgoing subgraph request.
    ///
    /// This is done in `on_subgraph_execute` (not `on_subgraph_http_request`)
    /// deliberately: the HTTP-request hook runs after the deduplication key is
    /// computed, so header changes there would not be reflected in dedup.
    async fn on_subgraph_execute<'exec>(
        &'exec self,
        mut payload: OnSubgraphExecuteStartHookPayload<'exec>,
    ) -> OnSubgraphExecuteStartHookResult<'exec> {
        if let Some(state) = payload.context.get_ref::<TokenState>() {
            let token = state.token.lock().unwrap();
            if let Some(value) = token.serialize_access_token() {
                if let Ok(header) = HeaderValue::from_str(&value) {
                    payload
                        .execution_request
                        .headers
                        .insert(HeaderName::from_static("x-access-token"), header);
                }
            }
            if let Some(value) = token.dump_refresh_token() {
                if let Ok(header) = HeaderValue::from_str(&value) {
                    payload
                        .execution_request
                        .headers
                        .insert(HeaderName::from_static("x-refresh-token"), header);
                }
            }
        }
        payload.proceed()
    }

    /// Read tokens minted/rotated by a subgraph back off its HTTP response and
    /// merge them into the shared token (tracking modifications so we know to
    /// (re)write cookies on the client response).
    async fn on_subgraph_http_request<'exec>(
        &'exec self,
        payload: OnSubgraphHttpRequestHookPayload<'exec>,
    ) -> OnSubgraphHttpRequestHookResult<'exec> {
        payload.on_end(|end| {
            if let Some(state) = end.context.get_ref::<TokenState>() {
                let mut token = state.token.lock().unwrap();
                if let Some(value) = end
                    .response
                    .headers
                    .get("x-access-token")
                    .and_then(|h| h.to_str().ok())
                {
                    token.deserialize_access_token(value, true);
                }
                if let Some(value) = end
                    .response
                    .headers
                    .get("x-refresh-token")
                    .and_then(|h| h.to_str().ok())
                {
                    token.load_refresh_token(value, true);
                }
            }
            end.proceed()
        })
    }

    /// Write cookies on the client response once the whole operation is done.
    fn on_http_request<'exec>(
        &'exec self,
        payload: OnHttpRequestHookPayload<'exec>,
    ) -> OnHttpRequestHookResult<'exec> {
        payload.on_end(move |end| {
            let Some(state) = end.context.get_ref::<TokenState>() else {
                return end.proceed();
            };
            let cookies = {
                let token = state.token.lock().unwrap();
                self.build_response_cookies(&token)
            };
            if cookies.is_empty() {
                return end.proceed();
            }
            end.map_response(move |mut response| {
                let headers = response.headers_mut();
                for cookie in cookies {
                    headers.append(SET_COOKIE, cookie);
                }
                response
            })
            .proceed()
        })
    }
}

impl FederatedTokenPlugin {
    /// Mirrors the Apollo `willSendResponse` cookie logic: cookies are only
    /// (re)written when a subgraph modified the token, and the user/guest cookie
    /// variant is chosen by `is_authenticated`.
    fn build_response_cookies(&self, t: &FederatedToken) -> Vec<CookieHeaderValue> {
        let cfg = &self.config;
        let mut out = Vec::new();

        if t.destroy_token {
            out.push(build_set_cookie(&deletion(USER_TOKEN, true, "/"), cfg));
            out.push(build_set_cookie(&deletion(GUEST_TOKEN, true, "/"), cfg));
            out.push(build_set_cookie(&deletion(USER_DATA, false, "/"), cfg));
            out.push(build_set_cookie(&deletion(GUEST_DATA, false, "/"), cfg));
            out.push(build_set_cookie(
                &deletion(REFRESH_TOKEN, true, &cfg.refresh_token_path),
                cfg,
            ));
            out.push(build_set_cookie(&deletion(USER_REFRESH_EXISTS, false, "/"), cfg));
            out.push(build_set_cookie(&deletion(GUEST_REFRESH_EXISTS, false, "/"), cfg));
            return out;
        }

        // Independent conditions, mirroring the Apollo `willSendResponse` logic.
        if t.access_token_modified {
            if let Some(exp) = t.access_expiry() {
                if let Ok(jwt) = self.signer.encrypt_access(&t.tokens, t.is_authenticated, exp) {
                    let name = if t.is_authenticated { USER_TOKEN } else { GUEST_TOKEN };
                    out.push(build_set_cookie(
                        &CookieSpec {
                            name,
                            value: &jwt,
                            http_only: true,
                            path: "/",
                            max_age: Some(cfg.user_token_max_age),
                        },
                        cfg,
                    ));
                }
            }
        }

        // Data cookie (`userData`/`guestData`) — readable; the storefront uses it
        // to detect an existing session. Written on value change even when
        // `values` is empty (guests), matching the Node lib's data-JWT behaviour.
        if t.value_modified {
            let subject = t.subject(self.signer.subject_token_key());
            if let Ok(jwt) = self.signer.sign_data(&t.values, subject.as_deref()) {
                let name = if t.is_authenticated { USER_DATA } else { GUEST_DATA };
                out.push(build_set_cookie(
                    &CookieSpec {
                        name,
                        value: &jwt,
                        http_only: false,
                        path: "/",
                        max_age: Some(cfg.user_token_max_age),
                    },
                    cfg,
                ));
            }
        }

        if t.refresh_token_modified && !t.refresh_tokens.is_empty() {
            if let Ok(jwt) = self.signer.encrypt_refresh(&t.refresh_tokens) {
                out.push(build_set_cookie(
                    &CookieSpec {
                        name: REFRESH_TOKEN,
                        value: &jwt,
                        http_only: true,
                        path: &cfg.refresh_token_path,
                        max_age: Some(cfg.refresh_token_max_age),
                    },
                    cfg,
                ));
                let exists = if t.is_authenticated {
                    USER_REFRESH_EXISTS
                } else {
                    GUEST_REFRESH_EXISTS
                };
                out.push(build_set_cookie(
                    &CookieSpec {
                        name: exists,
                        value: "1",
                        http_only: false,
                        path: "/",
                        max_age: Some(cfg.refresh_token_max_age),
                    },
                    cfg,
                ));
            }
        }

        out
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn strip_bearer(value: String) -> String {
    value
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .unwrap_or(value)
}
