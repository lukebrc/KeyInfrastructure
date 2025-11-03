use actix_web::{web, App, HttpServer};
use sqlx::{Pool, Postgres};
use sqlx::postgres::PgPoolOptions;
use dotenvy::dotenv;
use std::env;
mod auth;

pub struct AppState {
    pool: Pool<Postgres>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create Postgres pool");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { pool: pool.clone() }))
            .route("/login", web::post().to(auth::login))
            .route("/register", web::post().to(auth::register))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}