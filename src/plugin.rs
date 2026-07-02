use std::sync::Mutex;

use hive_router::async_trait;
use hive_router::http::header::{HeaderName, HeaderValue};
use hive_router::ntex::http::header::{
    HeaderName as ResponseHeaderName, HeaderValue as CookieHeaderValue, SET_COOKIE,
};
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
            let response_tokens = {
                let token = state.token.lock().unwrap();
                self.build_response(&token)
            };
            if response_tokens.is_empty() {
                return end.proceed();
            }
            end.map_response(move |mut response| {
                let headers = response.headers_mut();
                for cookie in response_tokens.cookies {
                    headers.append(SET_COOKIE, cookie);
                }
                for (name, value) in response_tokens.headers {
                    headers.insert(name, value);
                }
                response
            })
            .proceed()
        })
    }
}

/// Tokens to write on the client response: `Set-Cookie` headers plus, when
/// `set_response_headers` is enabled, the `x-*-token` headers carrying the same
/// JWT values (mirroring the Node `CompositeTokenSource` of cookies + headers).
struct ResponseTokens {
    cookies: Vec<CookieHeaderValue>,
    headers: Vec<(ResponseHeaderName, CookieHeaderValue)>,
}

impl ResponseTokens {
    fn is_empty(&self) -> bool {
        self.cookies.is_empty() && self.headers.is_empty()
    }
}

impl FederatedTokenPlugin {
    /// Mirrors the Apollo `willSendResponse` logic: tokens are only (re)written
    /// when a subgraph modified them, and the user/guest cookie variant is chosen
    /// by `is_authenticated`. Each (re)issued JWT is emitted both as a cookie and
    /// (when configured) as its `x-*-token` header, reusing the same value.
    ///
    /// Note: header emission is stateless — like the Node header source, it only
    /// *sets* (re)issued tokens and performs no deletions, so a token destroy
    /// clears cookies only.
    fn build_response(&self, t: &FederatedToken) -> ResponseTokens {
        let cfg = &self.config;
        let mut out = ResponseTokens {
            cookies: Vec::new(),
            headers: Vec::new(),
        };

        if t.destroy_token {
            out.cookies.push(build_set_cookie(&deletion(USER_TOKEN, true, "/"), cfg));
            out.cookies.push(build_set_cookie(&deletion(GUEST_TOKEN, true, "/"), cfg));
            out.cookies.push(build_set_cookie(&deletion(USER_DATA, false, "/"), cfg));
            out.cookies.push(build_set_cookie(&deletion(GUEST_DATA, false, "/"), cfg));
            out.cookies.push(build_set_cookie(
                &deletion(REFRESH_TOKEN, true, &cfg.refresh_token_path),
                cfg,
            ));
            out.cookies.push(build_set_cookie(&deletion(USER_REFRESH_EXISTS, false, "/"), cfg));
            out.cookies.push(build_set_cookie(&deletion(GUEST_REFRESH_EXISTS, false, "/"), cfg));
            return out;
        }

        // Independent conditions, mirroring the Apollo `willSendResponse` logic.
        if t.access_token_modified {
            if let Some(exp) = t.access_expiry() {
                if let Ok(jwt) = self.signer.encrypt_access(&t.tokens, t.is_authenticated, exp) {
                    let name = if t.is_authenticated { USER_TOKEN } else { GUEST_TOKEN };
                    out.cookies.push(build_set_cookie(
                        &CookieSpec {
                            name,
                            value: &jwt,
                            http_only: true,
                            path: "/",
                            max_age: Some(cfg.user_token_max_age),
                        },
                        cfg,
                    ));
                    self.push_header(&mut out, "x-access-token", &jwt);
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
                out.cookies.push(build_set_cookie(
                    &CookieSpec {
                        name,
                        value: &jwt,
                        http_only: false,
                        path: "/",
                        max_age: Some(cfg.user_token_max_age),
                    },
                    cfg,
                ));
                self.push_header(&mut out, "x-data-token", &jwt);
            }
        }

        if t.refresh_token_modified && !t.refresh_tokens.is_empty() {
            if let Ok(jwt) = self.signer.encrypt_refresh(&t.refresh_tokens) {
                out.cookies.push(build_set_cookie(
                    &CookieSpec {
                        name: REFRESH_TOKEN,
                        value: &jwt,
                        http_only: true,
                        path: &cfg.refresh_token_path,
                        max_age: Some(cfg.refresh_token_max_age),
                    },
                    cfg,
                ));
                self.push_header(&mut out, "x-refresh-token", &jwt);
                let exists = if t.is_authenticated {
                    USER_REFRESH_EXISTS
                } else {
                    GUEST_REFRESH_EXISTS
                };
                out.cookies.push(build_set_cookie(
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

    /// Append an `x-*-token` response header when header emission is enabled.
    /// A value that isn't a valid header (JWTs never are, in practice) is skipped.
    fn push_header(&self, out: &mut ResponseTokens, name: &'static str, value: &str) {
        if !self.config.set_response_headers {
            return;
        }
        if let Ok(header) = CookieHeaderValue::from_str(value) {
            out.headers
                .push((ResponseHeaderName::from_static(name), header));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginConfig;
    use crate::token::AccessToken;
    use serde_json::json;

    fn plugin(set_response_headers: bool) -> FederatedTokenPlugin {
        let config: PluginConfig = serde_json::from_value(json!({
            "issuer": "http://localhost:4000",
            "audience": "http://localhost:4000",
            "cookie_domain": "localhost",
            "encrypt_keys": [{ "id": "1", "secret": "12345678123456781234567812345678" }],
            "sign_keys": [{ "id": "1", "secret": "87654321876543218765432187654321" }],
            "set_response_headers": set_response_headers,
        }))
        .unwrap();
        let signer = TokenSigner::from_config(&config).unwrap();
        FederatedTokenPlugin { signer, config }
    }

    /// A token that a subgraph rotated: an access token + a refresh token, both
    /// flagged modified, authenticated. Exercises all three header kinds.
    fn rotated_token() -> FederatedToken {
        let mut t = FederatedToken::new();
        t.is_authenticated = true;
        t.tokens.insert(
            "commercetools".into(),
            AccessToken {
                token: "ct-token".into(),
                exp: now_secs() + 3600,
                sub: "customer-1".into(),
            },
        );
        t.refresh_tokens
            .insert("commercetools".into(), "refresh-xyz".into());
        t.access_token_modified = true;
        t.value_modified = true;
        t.refresh_token_modified = true;
        t
    }

    fn now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn header_names(out: &ResponseTokens) -> Vec<String> {
        out.headers
            .iter()
            .map(|(name, _)| name.as_str().to_string())
            .collect()
    }

    fn cookie_names(out: &ResponseTokens) -> Vec<String> {
        out.cookies
            .iter()
            .filter_map(|c| c.to_str().ok())
            .filter_map(|c| c.split('=').next().map(str::to_string))
            .collect()
    }

    #[test]
    fn emits_x_headers_alongside_cookies() {
        let out = plugin(true).build_response(&rotated_token());

        let mut names = header_names(&out);
        names.sort();
        assert_eq!(
            names,
            vec!["x-access-token", "x-data-token", "x-refresh-token"]
        );

        // Each header value equals the JWT written into the matching cookie.
        for (name, value) in &out.headers {
            let cookie_name = match name.as_str() {
                "x-access-token" => USER_TOKEN,
                "x-data-token" => USER_DATA,
                "x-refresh-token" => REFRESH_TOKEN,
                other => panic!("unexpected header {other}"),
            };
            let cookie = out
                .cookies
                .iter()
                .filter_map(|c| c.to_str().ok())
                .find(|c| c.starts_with(&format!("{cookie_name}=")))
                .unwrap_or_else(|| panic!("no cookie for {name}"));
            let cookie_value = cookie
                .split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|(_, v)| v)
                .unwrap();
            assert_eq!(cookie_value, value.to_str().unwrap());
        }
    }

    #[test]
    fn disabling_response_headers_keeps_cookies_only() {
        let out = plugin(false).build_response(&rotated_token());
        assert!(out.headers.is_empty(), "no x-headers when disabled");
        // Cookies are unaffected.
        assert!(cookie_names(&out).contains(&USER_TOKEN.to_string()));
    }

    #[test]
    fn destroy_clears_cookies_and_emits_no_headers() {
        let mut t = FederatedToken::new();
        t.destroy_token = true;
        let out = plugin(true).build_response(&t);

        // Header emission is set-only (like the Node header source), so a destroy
        // touches cookies only.
        assert!(out.headers.is_empty());
        let names = cookie_names(&out);
        assert!(names.contains(&USER_TOKEN.to_string()));
        assert!(names.contains(&REFRESH_TOKEN.to_string()));
    }
}
