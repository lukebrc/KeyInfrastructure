use actix_web::{middleware::Logger, web, App, HttpServer};
use crate::auth::{list_users, login, register, verify_token};
use crate::certificate::list_certificates;
use crate::middleware::JwtMiddlewareFactory;
use dotenv::dotenv;
use sqlx::{Postgres, Pool};
use sqlx::postgres::PgPoolOptions;
use std::env;
use log::LevelFilter;

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
            .route("/users", web::post().to(register)) // Public route for registration
            .route("/auth/login", web::post().to(login))
            .route("/auth/verify", web::get().to(verify_token))
            // Protected routes
            .service(
                web::scope("")
                    .wrap(JwtMiddlewareFactory)
                    .route("/users", web::get().to(list_users))
                    .route("/certificates", web::get().to(list_certificates)),
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_http;
    use actix_web::{http, test, App};
    use crate::auth::{LoginRequest, RegisterRequest};
    use serde_json::json;

    async fn setup_test_app() -> (impl actix_web::dev::Service<actix_http::Request, Response = actix_web::dev::ServiceResponse, Error = actix_web::Error>, Pool<Postgres>) {
        let _ = env_logger::builder().filter_level(LevelFilter::Debug).is_test(true).try_init();
        dotenv().ok();
        // If DATABASE_URL is not set, try loading it from .test-env
        if env::var("DATABASE_URL").is_err() {
            dotenv::from_filename(".test-env").ok();
        }
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests. Provide it in the environment or a .test-env file.");
        log::info!("Connecting to {}", database_url);
        let jwt_secret = "test_secret".to_string();

        let pool = PgPoolOptions::new()
            .max_connections(2) // Use a single connection for tests to ensure isolation
            .connect(&database_url)
            .await
            .expect("Failed to create Postgres connection pool for tests");

        // Set up the database schema in a block to ensure the connection is released
        {
            let mut conn = pool.acquire().await.expect("Failed to acquire connection from pool");
            
            sqlx::query("DROP TABLE IF EXISTS users CASCADE").execute(&mut *conn).await.unwrap();
            sqlx::query("DROP TYPE IF EXISTS user_role").execute(&mut *conn).await.unwrap();

            // Not all postgres users have permission to create extensions. This might fail.
            // It's better to ensure the extension is created by a superuser beforehand.
            // However, for a local test setup, this is often fine.
            sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto").execute(&mut *conn).await.ok(); // Use .ok() to ignore errors if the user doesn't have permission
            
            sqlx::query("CREATE TYPE user_role AS ENUM ('ADMIN', 'USER')").execute(&mut *conn).await.unwrap();
            
            sqlx::query(
                "CREATE TABLE users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role user_role NOT NULL
                )"
            ).execute(&mut *conn).await.unwrap();
            log::info!("Table users created");
        }

        let app_state = web::Data::new(AppState {
            pool: pool.clone(),
            jwt_secret,
        });

        let app = test::init_service(
            App::new()
                .app_data(app_state.clone())
                .route("/users", web::post().to(register))
                .route("/auth/login", web::post().to(login)),
        )
        .await;

        (app, pool)
    }

    #[actix_web::test]
    async fn test_register_and_login() {
        let (app, pool) = setup_test_app().await;
        let tx = pool.begin().await.unwrap();

        // AUTH-01: Register a new user with valid data
        let register_req = RegisterRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            pin: "12345678".to_string(),
        };
        let req = test::TestRequest::post().uri("/users").set_json(&register_req).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED, "AUTH-01 Failed: Successful registration");

        // AUTH-02: Attempt to register with an existing username
        let req = test::TestRequest::post().uri("/users").set_json(&register_req).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CONFLICT, "AUTH-02 Failed: Duplicate username registration");

        // AUTH-03: Attempt to register with a PIN shorter than 8 characters
        let short_pin_req = json!({
            "username": "anotheruser",
            "password": "password123",
            "pin": "123"
        });
        let req = test::TestRequest::post().uri("/users").set_json(&short_pin_req).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST, "AUTH-03 Failed: Short PIN registration");

        // AUTH-04: Log in with correct credentials
        let login_req = LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
        };
        let req = test::TestRequest::post().uri("/auth/login").set_json(&login_req).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK, "AUTH-04 Failed: Successful login");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["token"].as_str().is_some(), "AUTH-04 Failed: Token not found in response");

        // AUTH-05: Log in with an incorrect password
        let wrong_pass_req = LoginRequest {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
        };
        let req = test::TestRequest::post().uri("/auth/login").set_json(&wrong_pass_req).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED, "AUTH-05 Failed: Incorrect password login");

        // Rollback the transaction to clean up the database
        tx.rollback().await.unwrap();
    }
}