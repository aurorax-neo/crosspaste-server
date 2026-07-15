use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// Mirrors CrossPaste `FailResponse` shape: `{ "errorCode": n, "message": "..." }`
/// so existing clients can parse relay failures similarly.
#[derive(Debug, Serialize)]
pub struct FailBody {
    /// Matches CrossPaste `FailResponse.errorCode`
    #[serde(rename = "errorCode")]
    pub error_code: i32,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("missing appInstanceId")]
    MissingAppInstanceId,
    #[error("device not online: {0}")]
    DeviceOffline(String),
    #[error("device busy or overloaded")]
    DeviceBusy,
    #[error("proxy timeout")]
    ProxyTimeout,
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("room not found or expired")]
    RoomNotFound,
    #[error("room full")]
    RoomFull,
    #[error("internal: {0}")]
    Internal(String),
}

impl RelayError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::MissingAppInstanceId | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::DeviceOffline(_) | Self::RoomNotFound => StatusCode::NOT_FOUND,
            Self::DeviceBusy | Self::RoomFull => StatusCode::TOO_MANY_REQUESTS,
            Self::ProxyTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Align with CrossPaste StandardErrorCode where it makes sense.
    pub fn code(&self) -> i32 {
        match self {
            Self::Unauthorized => 2003,           // UNTRUSTED_IDENTITY-ish
            Self::MissingAppInstanceId => 1000,   // NOT_FOUND_APP_INSTANCE_ID
            Self::DeviceOffline(_) => 1000,
            Self::DeviceBusy => 0,
            Self::ProxyTimeout => 0,
            Self::BadRequest(_) => 2,             // INVALID_PARAMETER
            Self::RoomNotFound => 3,              // NOT_FOUND_API-ish
            Self::RoomFull => 2,
            Self::Internal(_) => 0,               // UNKNOWN_ERROR
        }
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = FailBody {
            error_code: self.code(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

pub type RelayResult<T> = Result<T, RelayError>;
