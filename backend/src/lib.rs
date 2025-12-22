// Re-export modules for integration tests
pub mod auth;
pub mod certificate;
pub mod db_model;
pub mod errors;
pub mod http_app;
pub mod middleware;

// Re-export commonly used types and functions
pub use auth::{register, login, list_users, verify_token, LoginRequest, RegisterRequest};
pub use certificate::{create_certificate_request, download_pkcs12, download_public_certificate, list_user_certificates};
pub use middleware::JwtMiddlewareFactory;
pub use db_model::AppState;
