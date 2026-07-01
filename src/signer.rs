use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use josekit::jwe::{Dir, JweHeader};
use josekit::jws::{JwsHeader, HS256};
use josekit::jwt::{self, JwtPayload, JwtPayloadValidator};
use serde_json::Value;

use crate::config::PluginConfig;
use crate::errors::TokenError;
use crate::token::AccessToken;

/// 90 days, matching the Node data + refresh JWT expiry (`60 * 60 * 24 * 90`).
const NINETY_DAYS_SECS: u64 = 60 * 60 * 24 * 90;

/// Claims that are NOT per-service refresh tokens when decoding a refresh JWE.
/// Mirrors the `knownKeys` skip-list in `loadRefreshJWT`.
const RESERVED_CLAIMS: &[&str] = &["jwe", "iat", "exp", "aud", "iss", "nbf", "sub", "jti"];

/// Ports `TokenSigner` + `KeyManager`. The first key in each list signs new
/// tokens; verification selects a key by the `kid` header. Encrypters/verifiers
/// are cheap to build, so they are constructed per call rather than stored.
pub struct TokenSigner {
    issuer: String,
    audience: String,
    subject_token_key: String,
    /// (kid, secret bytes); index 0 is the active signing key.
    encrypt_keys: Vec<(String, Vec<u8>)>,
    sign_keys: Vec<(String, Vec<u8>)>,
}

impl TokenSigner {
    pub fn from_config(config: &PluginConfig) -> Result<Self, String> {
        let encrypt_keys = collect_keys(&config.encrypt_keys, "encrypt_keys")?;
        let sign_keys = collect_keys(&config.sign_keys, "sign_keys")?;
        Ok(Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            subject_token_key: config.subject_token_key.clone(),
            encrypt_keys,
            sign_keys,
        })
    }

    pub fn subject_token_key(&self) -> &str {
        &self.subject_token_key
    }

    // --- Access token (JWE dir / A256GCM) --------------------------------

    pub fn encrypt_access(
        &self,
        tokens: &BTreeMap<String, AccessToken>,
        is_authenticated: bool,
        exp: i64,
    ) -> Result<String, TokenError> {
        let mut payload = JwtPayload::new();
        payload
            .set_claim("tokens", Some(serde_json::to_value(tokens).unwrap()))
            .map_err(invalid)?;
        payload
            .set_claim("isAuthenticated", Some(Value::Bool(is_authenticated)))
            .map_err(invalid)?;
        self.encrypt_jwt(payload, exp)
    }

    pub fn decrypt_access(
        &self,
        value: &str,
    ) -> Result<(BTreeMap<String, AccessToken>, bool), TokenError> {
        let payload = self.decrypt_jwt(value)?;
        let tokens = payload
            .claim("tokens")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let is_authenticated = payload
            .claim("isAuthenticated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok((tokens, is_authenticated))
    }

    // --- Refresh token (JWE dir / A256GCM) -------------------------------

    pub fn encrypt_refresh(
        &self,
        refresh_tokens: &BTreeMap<String, String>,
    ) -> Result<String, TokenError> {
        let mut payload = JwtPayload::new();
        for (service, token) in refresh_tokens {
            payload
                .set_claim(service, Some(Value::String(token.clone())))
                .map_err(invalid)?;
        }
        let exp = now_secs() + NINETY_DAYS_SECS as i64;
        self.encrypt_jwt(payload, exp)
    }

    pub fn decrypt_refresh(&self, value: &str) -> Result<BTreeMap<String, String>, TokenError> {
        let payload = self.decrypt_jwt(value)?;
        let mut refresh = BTreeMap::new();
        for (key, val) in payload.claims_set() {
            if RESERVED_CLAIMS.contains(&key.as_str()) {
                continue;
            }
            if let Some(s) = val.as_str() {
                refresh.insert(key.clone(), s.to_string());
            }
        }
        Ok(refresh)
    }

    // --- Data token (JWS HS256, signed but not encrypted) ----------------

    pub fn sign_data(
        &self,
        values: &BTreeMap<String, Value>,
        subject: Option<&str>,
    ) -> Result<String, TokenError> {
        let mut payload = JwtPayload::new();
        payload
            .set_claim("values", Some(serde_json::to_value(values).unwrap()))
            .map_err(invalid)?;
        if let Some(sub) = subject {
            payload.set_subject(sub);
        }
        payload.set_issuer(&self.issuer);
        payload.set_audience(vec![self.audience.clone()]);
        payload.set_issued_at(&SystemTime::now());
        payload.set_expires_at(&secs_to_time(now_secs() + NINETY_DAYS_SECS as i64));

        let (kid, key) = self.active_sign();
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(kid);

        let signer = HS256.signer_from_bytes(key).map_err(invalid)?;
        jwt::encode_with_signer(&payload, &header, &signer).map_err(invalid)
    }

    pub fn verify_data(&self, value: &str) -> Result<BTreeMap<String, Value>, TokenError> {
        let header = jwt::decode_header(value).map_err(invalid)?;
        let jws_header = header
            .as_any()
            .downcast_ref::<JwsHeader>()
            .ok_or_else(|| TokenError::Invalid("not a JWS".into()))?;
        let kid = jws_header
            .key_id()
            .ok_or_else(|| TokenError::Invalid("missing kid".into()))?;
        let key = self
            .sign_key(kid)
            .ok_or_else(|| TokenError::Invalid("unknown kid".into()))?;

        let verifier = HS256.verifier_from_bytes(key).map_err(invalid)?;
        let (payload, _header) = jwt::decode_with_verifier(value, &verifier).map_err(invalid)?;
        self.validate_claims(&payload)?;

        let values = payload
            .claim("values")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        Ok(values)
    }

    // --- internals -------------------------------------------------------

    fn encrypt_jwt(&self, mut payload: JwtPayload, exp: i64) -> Result<String, TokenError> {
        payload.set_issuer(&self.issuer);
        payload.set_audience(vec![self.audience.clone()]);
        payload.set_issued_at(&SystemTime::now());
        payload.set_expires_at(&secs_to_time(exp));

        let (kid, key) = self.active_encrypt();
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A256GCM");
        header.set_key_id(kid);
        // The Node signer also stamps `exp` in the protected header. It is
        // redundant (payload carries it too) but we mirror it for fidelity.
        let _ = header.set_claim("exp", Some(Value::from(exp)));

        let encrypter = Dir.encrypter_from_bytes(key).map_err(invalid)?;
        jwt::encode_with_encrypter(&payload, &header, &encrypter).map_err(invalid)
    }

    fn decrypt_jwt(&self, value: &str) -> Result<JwtPayload, TokenError> {
        // Header/decryption failures -> Invalid (400), matching the Node mapping
        // where non-claim jose errors become TokenInvalidError.
        let header = jwt::decode_header(value).map_err(invalid)?;
        let jwe_header = header
            .as_any()
            .downcast_ref::<JweHeader>()
            .ok_or_else(|| TokenError::Invalid("not a JWE".into()))?;
        let kid = jwe_header
            .key_id()
            .ok_or_else(|| TokenError::Invalid("missing kid".into()))?;
        let key = self
            .encrypt_key(kid)
            .ok_or_else(|| TokenError::Invalid("unknown kid".into()))?;

        let decrypter = Dir.decrypter_from_bytes(key).map_err(invalid)?;
        let (payload, _header) = jwt::decode_with_decrypter(value, &decrypter).map_err(invalid)?;
        self.validate_claims(&payload)?;
        Ok(payload)
    }

    /// iss/aud/exp validation. Any failure maps to `Expired` to match the Node
    /// behaviour (both `JWTClaimValidationFailed` and `JWTExpired` -> expired).
    fn validate_claims(&self, payload: &JwtPayload) -> Result<(), TokenError> {
        let mut validator = JwtPayloadValidator::new();
        validator.set_issuer(&self.issuer);
        validator.set_audience(&self.audience);
        validator.set_base_time(SystemTime::now());
        validator
            .validate(payload)
            .map_err(|e| TokenError::Expired(e.to_string()))
    }

    fn active_encrypt(&self) -> (&str, &[u8]) {
        let (id, key) = &self.encrypt_keys[0];
        (id, key)
    }
    fn active_sign(&self) -> (&str, &[u8]) {
        let (id, key) = &self.sign_keys[0];
        (id, key)
    }
    fn encrypt_key(&self, kid: &str) -> Option<&[u8]> {
        self.encrypt_keys
            .iter()
            .find(|(id, _)| id == kid)
            .map(|(_, k)| k.as_slice())
    }
    fn sign_key(&self, kid: &str) -> Option<&[u8]> {
        self.sign_keys
            .iter()
            .find(|(id, _)| id == kid)
            .map(|(_, k)| k.as_slice())
    }
}

fn collect_keys(
    keys: &[crate::config::KeyConfig],
    label: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if keys.is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(keys
        .iter()
        .map(|k| (k.id.clone(), k.secret.as_bytes().to_vec()))
        .collect())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn secs_to_time(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
}

fn invalid(e: impl std::fmt::Display) -> TokenError {
    TokenError::Invalid(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginConfig;
    use serde_json::json;

    fn signer() -> TokenSigner {
        // Same keys the Apollo gateway hard-coded, so this also exercises the
        // exact byte layout old tokens were minted with.
        let cfg: PluginConfig = serde_json::from_value(json!({
            "issuer": "http://localhost:4000",
            "audience": "http://localhost:4000",
            "cookie_domain": "localhost",
            "encrypt_keys": [{ "id": "1", "secret": "12345678123456781234567812345678" }],
            "sign_keys": [{ "id": "1", "secret": "87654321876543218765432187654321" }]
        }))
        .unwrap();
        TokenSigner::from_config(&cfg).unwrap()
    }

    fn future() -> i64 {
        now_secs() + 3600
    }

    #[test]
    fn access_token_roundtrip() {
        let s = signer();
        let mut tokens = BTreeMap::new();
        tokens.insert(
            "commercetools".to_string(),
            AccessToken {
                token: "ct-token".into(),
                exp: future(),
                sub: "customer-1".into(),
            },
        );
        let jwt = s.encrypt_access(&tokens, true, future()).unwrap();
        let (out, is_auth) = s.decrypt_access(&jwt).unwrap();
        assert!(is_auth);
        assert_eq!(out.get("commercetools").unwrap().token, "ct-token");
    }

    #[test]
    fn refresh_token_roundtrip() {
        let s = signer();
        let mut refresh = BTreeMap::new();
        refresh.insert("commercetools".to_string(), "refresh-xyz".to_string());
        let jwt = s.encrypt_refresh(&refresh).unwrap();
        let out = s.decrypt_refresh(&jwt).unwrap();
        assert_eq!(out.get("commercetools").unwrap(), "refresh-xyz");
    }

    #[test]
    fn data_token_roundtrip() {
        let s = signer();
        let mut values = BTreeMap::new();
        values.insert("firstName".to_string(), json!("Ada"));
        let jwt = s.sign_data(&values, Some("customer-1")).unwrap();
        let out = s.verify_data(&jwt).unwrap();
        assert_eq!(out.get("firstName").unwrap(), &json!("Ada"));
    }
}
