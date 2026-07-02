use serde::Deserialize;

/// Plugin configuration, deserialized from the `plugins.federated_token.config`
/// block in the router YAML.
///
/// Hive Router does NOT interpolate `${ENV_VAR}` in config values (it only has a
/// fixed set of built-in env overrides), so string fields here may still contain
/// `${VAR}` after deserialization. [`PluginConfig::resolve_env`] expands them at
/// init time — keep secrets in the environment and reference them as `${VAR}`.
#[derive(Debug, Deserialize)]
pub struct PluginConfig {
    /// `iss` claim, validated on every token. Matches GRAPHQL_GATEWAY_JWT_ISSUER.
    pub issuer: String,
    /// `aud` claim, validated on every token. Matches GRAPHQL_GATEWAY_JWT_AUDIENCE.
    pub audience: String,

    /// Symmetric keys for the JWE access + refresh tokens (dir / A256GCM).
    /// The first key in the list signs new tokens; all keys are candidates for
    /// verification, selected by the `kid` header. Each secret must be 32 bytes.
    pub encrypt_keys: Vec<KeyConfig>,
    /// Symmetric keys for the JWS data token (HS256). Same rotation semantics.
    pub sign_keys: Vec<KeyConfig>,

    /// Cookie domain. Matches GRAPHQL_GATEWAY_COOKIE_DOMAIN.
    pub cookie_domain: String,

    #[serde(default = "default_true")]
    pub secure: bool,
    #[serde(default = "default_same_site")]
    pub same_site: SameSite,

    /// Path scoping for the refresh-token cookie so it is only sent to the
    /// refresh endpoint. Matches the Apollo config `refreshTokenPath`.
    #[serde(default = "default_refresh_path")]
    pub refresh_token_path: String,

    /// Access-token cookie max-age in seconds (2 days in the Apollo config).
    #[serde(default = "default_user_token_max_age")]
    pub user_token_max_age: i64,
    /// Refresh-token cookie max-age in seconds (200 days in the Apollo config).
    #[serde(default = "default_refresh_token_max_age")]
    pub refresh_token_max_age: i64,

    /// Which entry in `tokens` provides the `sub` for the data JWT.
    /// The Apollo config used `token.tokens.commercetools?.sub`.
    #[serde(default = "default_subject_key")]
    pub subject_token_key: String,

    /// Also emit the (re)issued tokens as `x-access-token` / `x-data-token` /
    /// `x-refresh-token` response headers, alongside the `Set-Cookie` headers.
    ///
    /// The Node gateway used a `CompositeTokenSource` (cookies + headers), so
    /// clients that read the tokens from headers instead of cookies relied on
    /// these. Enabled by default to preserve that behaviour.
    #[serde(default = "default_true")]
    pub set_response_headers: bool,
}

impl PluginConfig {
    /// Expand `${VAR}` references in the string fields from the environment,
    /// because Hive Router doesn't interpolate config values itself. Unset
    /// variables expand to an empty string. Call once at plugin init.
    pub fn resolve_env(&mut self) {
        self.issuer = expand_env(&self.issuer);
        self.audience = expand_env(&self.audience);
        self.cookie_domain = expand_env(&self.cookie_domain);
        for key in &mut self.encrypt_keys {
            key.secret = expand_env(&key.secret);
        }
        for key in &mut self.sign_keys {
            key.secret = expand_env(&key.secret);
        }
    }
}

/// Replace every `${VAR}` in `value` with the corresponding environment
/// variable (unset -> empty). ASCII delimiters keep this UTF-8 safe.
fn expand_env(value: &str) -> String {
    let mut result = value.to_string();
    let mut search_from = 0;
    while let Some(rel) = result[search_from..].find("${") {
        let start = search_from + rel;
        let Some(end_rel) = result[start + 2..].find('}') else {
            break;
        };
        let end = start + 2 + end_rel;
        let var = &result[start + 2..end];
        let replacement = std::env::var(var).unwrap_or_default();
        // Advance past the replacement so a value containing `${` can't loop.
        search_from = start + replacement.len();
        result.replace_range(start..=end, &replacement);
    }
    result
}

#[derive(Debug, Deserialize)]
pub struct KeyConfig {
    pub id: String,
    /// Raw secret. Its UTF-8 bytes are used directly as the key, matching the
    /// Node `createSecretKey(Buffer.from(secret))`. Must be exactly 32 bytes for
    /// A256GCM / HS256.
    pub secret: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_same_site() -> SameSite {
    SameSite::Lax
}
fn default_refresh_path() -> String {
    "/auth/graphql".to_string()
}
fn default_user_token_max_age() -> i64 {
    2 * 24 * 60 * 60
}
fn default_refresh_token_max_age() -> i64 {
    200 * 24 * 60 * 60
}
fn default_subject_key() -> String {
    "commercetools".to_string()
}

#[cfg(test)]
mod tests {
    use super::expand_env;

    #[test]
    fn expands_and_passes_through() {
        // SAFETY: single-threaded test; set a unique var name.
        std::env::set_var("FEDTOKEN_TEST_DOMAIN", "localhost");
        assert_eq!(expand_env("${FEDTOKEN_TEST_DOMAIN}"), "localhost");
        assert_eq!(
            expand_env("pre-${FEDTOKEN_TEST_DOMAIN}-post"),
            "pre-localhost-post"
        );
        // A plain value is unchanged; an unset var expands to empty.
        assert_eq!(expand_env("plain-value"), "plain-value");
        assert_eq!(expand_env("${FEDTOKEN_TEST_UNSET_XYZ}"), "");
        std::env::remove_var("FEDTOKEN_TEST_DOMAIN");
    }
}
