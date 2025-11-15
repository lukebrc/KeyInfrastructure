use actix_web::{middleware::Logger, web, App, HttpServer};
use crate::auth::{login, register, verify_token};
use crate::certificate::list_certificates;
use crate::middleware::JwtMiddlewareFactory;
use dotenv::dotenv;
use sqlx::{Postgres, Pool};
use sqlx::postgres::PgPoolOptions;
use std::env;

mod auth;
mod certificate;
mod db_model;
mod errors;
mod middleware;

pub struct AppState {
    pub pool: Pool<Postgres>,
    pub jwt_secret: String,
}

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
            .route("/users", web::post().to(register))
            .route("/auth/login", web::post().to(login))
            .route("/auth/verify", web::get().to(verify_token))
            .service(
                web::resource("/certificates")
                    .wrap(JwtMiddlewareFactory)
                    .route(web::get().to(list_certificates)),
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}