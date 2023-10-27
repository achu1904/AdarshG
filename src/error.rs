use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OcppServerError {
    #[error("Unsupported OCPP version")]
    UnsupportedOcppVersion,
    #[error("Unknown OCPP version")]
    UnknownOcppVersion,
    #[error("unknown  error")]
    Unknown,
}

impl IntoResponse for OcppServerError {
    fn into_response(self) -> Response {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            format!("Something went wrong: {}", self),
        )
            .into_response()
    }
}
