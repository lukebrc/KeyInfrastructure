use actix_http;
use actix_web::{http, test, App, web};
use dotenv::dotenv;
use login::auth::{LoginRequest, RegisterRequest};
use login::*;
use serde_json::json;
use sqlx::{Postgres, Pool};
use sqlx::postgres::PgPoolOptions;
use std::env;
use log::LevelFilter;

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
            .route("/auth/login", web::post().to(login))
            .service(
                web::scope("")
                    .wrap(JwtMiddlewareFactory)
                    .route("/certificates", web::get().to(list_active_certificates))
                    .route("/certificates", web::post().to(create_certificate_request))
                    .route("/certificates/{cert_id}/download", web::post().to(download_certificate)),
            ),
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

#[actix_web::test]
async fn test_admin_register_and_login() {
    let (app, pool) = setup_test_app().await;
    let mut tx = pool.begin().await.unwrap();

    let admin_name = "admin";
    let admin_password = "password123";

    // AUTH-01: Register a new user with valid data
    let register_req = RegisterRequest {
        username: admin_name.to_string(),
        password: admin_password.to_string(),
        pin: "12345678".to_string(),
    };
    let req = test::TestRequest::post().uri("/users").set_json(&register_req).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::CREATED, "AUTH-01 Failed: Successful registration");

    //change user type manually
    let update_result = sqlx::query("UPDATE users set role = 'ADMIN' where username = $1")
        .bind(admin_name)
        .execute(&mut *tx)
        .await
        .unwrap();

    assert_eq!(1, update_result.rows_affected());
    tx.commit().await.unwrap();

    // AUTH-04: Log in with correct credentials
    let login_req = LoginRequest {
        username: admin_name.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post().uri("/auth/login").set_json(&login_req).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "AUTH-04 Failed: Successful login");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["token"].as_str().is_some(), "AUTH-04 Failed: Token not found in response");
    let user = &body["user"];
    assert_eq!(user["role"].as_str().unwrap(), "ADMIN", "User should be logged in as admin");
}

#[actix_web::test]
async fn test_certificate_lifecycle() {
    let (app, pool) = setup_test_app().await;
    let mut tx: sqlx::Transaction<'_, Postgres> = pool.begin().await.unwrap();
    let admin_user = "adminuser";
    let admin_password= "adminpass";
    let password_hash = bcrypt::hash(admin_password, 12).unwrap();

    // 1. Register an admin and a regular user
    sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'ADMIN')")
        .bind(admin_user)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let test_user = "certuser";
    let test_password = "password123";

    let register_req = RegisterRequest {
        username: test_user.to_string(),
        password: test_password.to_string(),
        pin: "87654321".to_string(),
    };
    let req = test::TestRequest::post().uri("/users").set_json(&register_req).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::CREATED, "Failed to register user for cert test");
    let user_body: serde_json::Value = test::read_body_json(resp).await;
    let user_id = user_body["id"].as_str().unwrap();

    // 2. Admin logs in
    let login_req = LoginRequest {
        username: admin_user.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post().uri("/auth/login").set_json(&login_req).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "Admin login failed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let admin_token = body["token"].as_str().unwrap();
    assert_eq!(body["user"]["role"].as_str().unwrap(), "ADMIN", "Admin should be logged in as admin");

    // 3. CERT-01: Admin creates a certificate request for the user
    let create_cert_req = json!({
        "user_id": user_id,
        "dn": "CN=certuser/O=org/C=PL",
        "days_valid": 365,
    });
    let req = test::TestRequest::post()
        .uri("/certificates")
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&create_cert_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::CREATED, "CERT-01 Failed: Certificate request creation");
    let cert_body: serde_json::Value = test::read_body_json(resp).await;
    let cert_id = cert_body["id"].as_str().unwrap();

    // 4. Regular user logs in
    let user_login_req = LoginRequest {
        username: test_user.to_string(),
        password: test_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&user_login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "User login failed");
    let user_login_body: serde_json::Value = test::read_body_json(resp).await;
    let user_token = user_login_body["token"].as_str().unwrap();
    assert_eq!(user_login_body["user"]["role"].as_str().unwrap(), "USER", "User should be logged in as a USER");

    // 5. CERT-03: User get list of available certificate requests
    let req = test::TestRequest::get()
        .uri("/certificates/pending")
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "CERT-03 Failed: Get certificate requests");
    let list_body: serde_json::Value = test::read_body_json(resp).await;
    assert!(list_body["certificates"].is_array(), "CERT-03 Failed: Certificates should be array");
    let certs = list_body["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 1, "CERT-03 Failed: Should have one certificate request");
    let cert = &certs[0];
    assert_eq!(cert["dn"].as_str().unwrap(), "CN=certuser/O=org/C=PL", "CERT-03 Failed: DN mismatch");

    // 6. CERT-04: User generate certificate basing on pending certificate request
    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nDummyCSR\n-----END CERTIFICATE REQUEST-----";
    let generate_req = json!({ "csr": csr });
    let generate_uri = format!("/certificates/{}/generate", cert_id);
    let req = test::TestRequest::post()
        .uri(&generate_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .set_json(&generate_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "CERT-04 Failed: Generate certificate");

    // 7. CERT-05: User downloads their certificate with the correct PIN
    let download_req = json!({ "pin": "87654321" });
    let download_uri = format!("/certificates/{}/download", cert_id);
    let req = test::TestRequest::post()
        .uri(&download_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .set_json(&download_req)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "CERT-05 Failed: Certificate download with correct PIN");

    let content_type = resp.headers().get(http::header::CONTENT_TYPE).unwrap();
    assert_eq!(content_type, "application/octet-stream", "CERT-05 Failed: Incorrect content type for download");

    let body_bytes = test::read_body(resp).await;
    assert!(!body_bytes.is_empty(), "CERT-05 Failed: Downloaded file is empty");
}
