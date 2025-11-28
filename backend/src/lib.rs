// Re-export modules for integration tests
pub mod auth;
pub mod certificate;
pub mod middleware;
pub mod db_model;
pub mod errors;

// Re-export commonly used types and functions
pub use auth::{register, login, list_users, verify_token, LoginRequest, RegisterRequest};
pub use certificate::{create_certificate, download_certificate, list_certificates};
pub use middleware::JwtMiddlewareFactory;
pub use db_model::AppState;
