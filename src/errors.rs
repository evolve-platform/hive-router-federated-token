use hive_router::http::StatusCode;
use hive_router::GraphQLError;

/// Mirrors `@labdigital/federated-token`'s error split.
///
/// In the Node implementation (`errors.ts`), jose's `JWTClaimValidationFailed`
/// (issuer/audience mismatch) and `JWTExpired` both map to `TokenExpiredError`,
/// while any other failure maps to `TokenInvalidError`. We keep that mapping so
/// the client-observable error codes/status match the Apollo gateway exactly.
#[derive(Debug)]
pub enum TokenError {
    /// Expired, or issuer/audience claim mismatch. -> 401 UNAUTHENTICATED
    Expired(String),
    /// Malformed, wrong key, decryption/signature failure. -> 400 INVALID_TOKEN
    Invalid(String),
}

impl TokenError {
    pub fn graphql_error(&self) -> GraphQLError {
        match self {
            TokenError::Expired(_) => {
                GraphQLError::from_message_and_code("Your token has expired.", "UNAUTHENTICATED")
            }
            TokenError::Invalid(_) => {
                GraphQLError::from_message_and_code("Your token is invalid.", "INVALID_TOKEN")
            }
        }
    }

    /// Note the historical quirk carried over from the Apollo gateway: the
    /// `TokenInvalidError` path used code `INVALID_TOKEN` but HTTP 400, while the
    /// expired path uses 401. We preserve both.
    pub fn status_code(&self) -> StatusCode {
        match self {
            TokenError::Expired(_) => StatusCode::UNAUTHORIZED,
            TokenError::Invalid(_) => StatusCode::BAD_REQUEST,
        }
    }
}
