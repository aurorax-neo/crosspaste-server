use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// Mirrors CrossPaste `FailResponse` shape: `{ "errorCode": n, "message": "..." }`.
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
    #[error("targetAppInstanceId does not match this server")]
    AppInstanceMismatch,
    #[error("client key is missing or cannot decrypt payload")]
    DecryptFail,
    #[error("device not online: {0}")]
    DeviceOffline(String),
    #[error("resource not found: {0}")]
    ResourceNotFound(String),
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
            Self::MissingAppInstanceId
            | Self::AppInstanceMismatch
            | Self::DecryptFail
            | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::DeviceOffline(_) | Self::ResourceNotFound(_) | Self::RoomNotFound => {
                StatusCode::NOT_FOUND
            }
            Self::DeviceBusy | Self::RoomFull => StatusCode::TOO_MANY_REQUESTS,
            Self::ProxyTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Align with CrossPaste StandardErrorCode where it makes sense.
    pub fn code(&self) -> i32 {
        match self {
            Self::Unauthorized => 2003,         // UNTRUSTED_IDENTITY-ish
            Self::MissingAppInstanceId => 1000, // NOT_FOUND_APP_INSTANCE_ID
            Self::AppInstanceMismatch => 1011,
            Self::DecryptFail => 2008,
            Self::DeviceOffline(_) => 1000,
            Self::ResourceNotFound(_) => 1003,
            Self::DeviceBusy => 0,
            Self::ProxyTimeout => 0,
            Self::BadRequest(_) => 2, // INVALID_PARAMETER
            Self::RoomNotFound => 3,  // NOT_FOUND_API-ish
            Self::RoomFull => 2,
            Self::Internal(_) => 0, // UNKNOWN_ERROR
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
