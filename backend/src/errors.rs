use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Not Found: {0}")]
    NotFound(String),
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::Database(_) => HttpResponse::InternalServerError().json("Database error"),
            ApiError::Unauthorized(msg) => HttpResponse::Unauthorized().json(msg),
            ApiError::BadRequest(msg) => HttpResponse::BadRequest().json(msg),
            ApiError::Internal(msg) => HttpResponse::InternalServerError().json(msg),
            ApiError::Conflict(msg) => HttpResponse::Conflict().json(msg),
            ApiError::Forbidden(msg) => HttpResponse::Forbidden().json(msg),
            ApiError::NotFound(msg) => HttpResponse::NotFound().json(msg),
        }
    }
}
