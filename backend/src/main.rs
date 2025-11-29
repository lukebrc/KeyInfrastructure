use actix_web::{middleware::Logger, web, App, HttpServer};
use crate::auth::{list_users, login, register, verify_token};
use crate::certificate::{create_certificate_request, download_certificate, generate_certificate, list_active_certificates, list_pending_certificates};
use crate::db_model::AppState;
use crate::middleware::JwtMiddlewareFactory;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
mod auth;
mod certificate;
mod db_model;
mod errors;
mod middleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create Postgres connection pool");

    let app_state = web::Data::new(AppState { pool, jwt_secret });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .route("/users", web::post().to(register)) // Public route for registration
            .route("/auth/login", web::post().to(login))
            .route("/auth/verify", web::get().to(verify_token))
            // Protected routes
            .service(
                web::scope("/certificates")
                    .wrap(JwtMiddlewareFactory)
                    .route("/pending", web::get().to(list_pending_certificates))
                    .route("/active", web::get().to(list_active_certificates))
                    //.route("/certificates/expiring", web::get().to(list_expiring_certificates))
                    .route("/{cert_id}/download", web::post().to(download_certificate))
                    .route("/{cert_id}/generate", web::post().to(generate_certificate))
                    .route("/", web::post().to(create_certificate_request)),
            )
            .service(
                web::scope("/users")
                    .wrap(JwtMiddlewareFactory)
                    .route("/users", web::get().to(list_users))
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
