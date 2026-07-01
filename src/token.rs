use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A per-subgraph access token, mirroring `AccessToken` in token.ts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessToken {
    pub token: String,
    pub exp: i64,
    pub sub: String,
}

/// The wire object that is JSON-encoded then base64 (standard alphabet, NOT
/// url-safe) into the `x-access-token` header between gateway and subgraphs.
///
/// Encoding is sparse: only non-empty fields are present, matching
/// `serializeAccessToken()` in token.ts.
#[derive(Debug, Default, Serialize, Deserialize)]
struct FederatedTokenValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    is_authenticated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destroy_token: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tokens: Option<BTreeMap<String, AccessToken>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    values: Option<BTreeMap<String, Value>>,
}

// serde renames to keep the JSON keys identical to the TS wire format
// (`isAuthenticated`, `destroyToken`).
impl FederatedTokenValue {
    const IS_AUTHENTICATED: &'static str = "isAuthenticated";
    const DESTROY_TOKEN: &'static str = "destroyToken";
}

/// The mutable per-request token state, mirroring the `FederatedToken` class.
///
/// The `*_modified` flags drive whether cookies are (re)written on the response,
/// exactly like the Apollo `willSendResponse` logic.
#[derive(Debug, Default)]
pub struct FederatedToken {
    pub tokens: BTreeMap<String, AccessToken>,
    pub refresh_tokens: BTreeMap<String, String>,
    pub values: BTreeMap<String, Value>,

    pub is_authenticated: bool,
    pub destroy_token: bool,

    pub access_token_modified: bool,
    pub refresh_token_modified: bool,
    pub value_modified: bool,
}

impl FederatedToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Earliest per-subgraph token expiry, used as the JWE `exp`. Mirrors
    /// `getExpireTime()`. Returns None when there are no tokens.
    pub fn access_expiry(&self) -> Option<i64> {
        self.tokens.values().map(|t| t.exp).min()
    }

    /// Serialize the access token wire value (base64 of sparse JSON) for a
    /// subgraph request. Returns None when there is nothing to send, matching
    /// `serializeAccessToken()`.
    pub fn serialize_access_token(&self) -> Option<String> {
        let mut map = serde_json::Map::new();
        if !self.tokens.is_empty() {
            map.insert(
                "tokens".into(),
                serde_json::to_value(&self.tokens).ok()?,
            );
        }
        if !self.values.is_empty() {
            map.insert(
                "values".into(),
                serde_json::to_value(&self.values).ok()?,
            );
        }
        if self.is_authenticated {
            map.insert(FederatedTokenValue::IS_AUTHENTICATED.into(), Value::Bool(true));
        }
        if self.destroy_token {
            map.insert(FederatedTokenValue::DESTROY_TOKEN.into(), Value::Bool(true));
        }
        if map.is_empty() {
            return None;
        }
        let json = serde_json::to_vec(&Value::Object(map)).ok()?;
        Some(BASE64.encode(json))
    }

    /// Refresh token wire value (base64 of the `{service: token}` map). Mirrors
    /// `dumpRefreshToken()`.
    pub fn dump_refresh_token(&self) -> Option<String> {
        if self.refresh_tokens.is_empty() {
            return None;
        }
        let json = serde_json::to_vec(&self.refresh_tokens).ok()?;
        Some(BASE64.encode(json))
    }

    /// Merge an access token wire value received from a subgraph response.
    /// Mirrors `deserializeAccessToken(at, trackModified)`: fields are merged,
    /// not replaced, and modification flags are set when `track_modified`.
    pub fn deserialize_access_token(&mut self, encoded: &str, track_modified: bool) {
        let Ok(raw) = BASE64.decode(encoded) else {
            return;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
            return;
        };
        let obj = match value {
            Value::Object(o) => o,
            _ => return,
        };

        let incoming_tokens: BTreeMap<String, AccessToken> = obj
            .get("tokens")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        // Distinguish "no values key" (undefined) from an explicit empty object,
        // to mirror the Node lib's `!isDeepStrictEqual(this.values, token.values)`.
        let has_values_key = obj.contains_key("values");
        let incoming_values: BTreeMap<String, Value> = obj
            .get("values")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        if track_modified {
            // The Node lib treats a token whose `values` is absent (undefined) as
            // value-modified, because `isDeepStrictEqual({}, undefined)` is false.
            // That is what makes guests still receive a (readable) data cookie
            // (`guestData`) — which the storefront uses to detect an existing
            // session (`use-ensure-session`). Preserve that behaviour.
            if !has_values_key || incoming_values != self.values {
                self.value_modified = true;
            }
            let tokens_changed = incoming_tokens
                .iter()
                .any(|(k, v)| self.tokens.get(k) != Some(v));
            if tokens_changed {
                self.access_token_modified = true;
            }
        }

        if obj
            .get(FederatedTokenValue::IS_AUTHENTICATED)
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            self.is_authenticated = true;
        }
        if obj
            .get(FederatedTokenValue::DESTROY_TOKEN)
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            self.destroy_token = true;
        }

        self.tokens.extend(incoming_tokens);
        self.values.extend(incoming_values);
    }

    /// Merge refresh tokens received from a subgraph response. Mirrors
    /// `loadRefreshToken(rt, trackModified)`.
    pub fn load_refresh_token(&mut self, encoded: &str, track_modified: bool) {
        let Ok(raw) = BASE64.decode(encoded) else {
            return;
        };
        let Ok(incoming) = serde_json::from_slice::<BTreeMap<String, String>>(&raw) else {
            return;
        };
        if track_modified && incoming.iter().any(|(k, v)| self.refresh_tokens.get(k) != Some(v)) {
            self.refresh_token_modified = true;
        }
        self.refresh_tokens.extend(incoming);
    }

    /// Subject for the data JWT, e.g. `tokens.commercetools.sub`. Mirrors the
    /// `getSubject` hook configured on the Apollo gateway.
    pub fn subject(&self, subject_token_key: &str) -> Option<String> {
        self.tokens.get(subject_token_key).map(|t| t.sub.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_token() -> AccessToken {
        AccessToken {
            token: "ct-jwt".into(),
            exp: 1_700_000_000,
            sub: "customer-1".into(),
        }
    }

    #[test]
    fn serializes_sparse_and_decodes_to_known_json() {
        let mut t = FederatedToken::new();
        t.tokens.insert("commercetools".into(), sample_token());
        t.is_authenticated = true;

        let encoded = t.serialize_access_token().expect("should serialize");
        let decoded: Value = serde_json::from_slice(&BASE64.decode(&encoded).unwrap()).unwrap();

        assert_eq!(
            decoded,
            json!({
                "tokens": { "commercetools": { "token": "ct-jwt", "exp": 1_700_000_000, "sub": "customer-1" } },
                "isAuthenticated": true
            })
        );
    }

    #[test]
    fn empty_token_serializes_to_none() {
        assert!(FederatedToken::new().serialize_access_token().is_none());
    }

    #[test]
    fn deserialize_merges_and_tracks_modifications() {
        let mut t = FederatedToken::new();
        t.tokens.insert("catalog".into(), sample_token());

        let mut incoming = FederatedToken::new();
        incoming.tokens.insert("commercetools".into(), sample_token());
        incoming.is_authenticated = true;
        let wire = incoming.serialize_access_token().unwrap();

        t.deserialize_access_token(&wire, true);

        assert!(t.access_token_modified);
        assert!(t.is_authenticated);
        // merged, not replaced
        assert!(t.tokens.contains_key("catalog"));
        assert!(t.tokens.contains_key("commercetools"));
    }

    #[test]
    fn missing_values_key_marks_value_modified() {
        // A guest subgraph response carries tokens but no `values` key. The Node
        // lib treats that as value-modified, so a (readable) data cookie is still
        // written — which the storefront needs to detect a session.
        let mut t = FederatedToken::new();
        let mut incoming = FederatedToken::new();
        incoming.tokens.insert("commercetools".into(), sample_token());
        let wire = incoming.serialize_access_token().unwrap();
        assert!(
            !wire_contains_values(&wire),
            "guest wire should omit the values key"
        );

        t.deserialize_access_token(&wire, true);

        assert!(t.value_modified, "absent values key must mark value modified");
        assert!(t.values.is_empty());
    }

    fn wire_contains_values(encoded: &str) -> bool {
        let raw = BASE64.decode(encoded).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        value.get("values").is_some()
    }

    #[test]
    fn refresh_token_wire_roundtrips() {
        let mut t = FederatedToken::new();
        t.refresh_tokens.insert("commercetools".into(), "refresh-abc".into());

        let wire = t.dump_refresh_token().unwrap();
        let mut loaded = FederatedToken::new();
        loaded.load_refresh_token(&wire, true);

        assert_eq!(loaded.refresh_tokens.get("commercetools").unwrap(), "refresh-abc");
        assert!(loaded.refresh_token_modified);
    }
}
