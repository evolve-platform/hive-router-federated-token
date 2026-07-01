use std::collections::HashMap;

use hive_router::ntex::http::header::HeaderValue;
use hive_router::ntex::http::HeaderMap;

use crate::config::PluginConfig;

/// Default cookie names, matching `DEFAULT_COOKIE_NAMES` in cookies-base.ts.
pub const USER_DATA: &str = "userData";
pub const GUEST_DATA: &str = "guestData";
pub const USER_TOKEN: &str = "userToken";
pub const GUEST_TOKEN: &str = "guestToken";
pub const REFRESH_TOKEN: &str = "refreshToken";
pub const USER_REFRESH_EXISTS: &str = "userRefreshTokenExists";
pub const GUEST_REFRESH_EXISTS: &str = "guestRefreshTokenExists";

/// Parse the `Cookie` request header into a name -> value map.
pub fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    if let Some(header) = headers.get("cookie") {
        if let Ok(s) = header.to_str() {
            for pair in s.split(';') {
                if let Some((name, value)) = pair.trim().split_once('=') {
                    cookies.insert(name.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }
    cookies
}

/// Attributes for a single `Set-Cookie`. `max_age` of `None` yields a session
/// cookie; `Some(0)` (via [`deletion`]) expires it immediately.
pub struct CookieSpec<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub http_only: bool,
    pub path: &'a str,
    pub max_age: Option<i64>,
}

pub fn build_set_cookie(spec: &CookieSpec, config: &PluginConfig) -> HeaderValue {
    let mut out = format!("{}={}; Path={}", spec.name, spec.value, spec.path);
    if !config.cookie_domain.is_empty() {
        out.push_str(&format!("; Domain={}", config.cookie_domain));
    }
    if let Some(max_age) = spec.max_age {
        out.push_str(&format!("; Max-Age={max_age}"));
    }
    if config.secure {
        out.push_str("; Secure");
    }
    if spec.http_only {
        out.push_str("; HttpOnly");
    }
    out.push_str(&format!("; SameSite={}", config.same_site.as_str()));

    // Cookie names/values are validated upstream, so this parse cannot fail in
    // practice; fall back to an empty-but-valid header rather than panicking.
    HeaderValue::from_str(&out).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// A cookie spec that clears an existing cookie (empty value, Max-Age=0).
pub fn deletion<'a>(name: &'a str, http_only: bool, path: &'a str) -> CookieSpec<'a> {
    CookieSpec {
        name,
        value: "",
        http_only,
        path,
        max_age: Some(0),
    }
}
