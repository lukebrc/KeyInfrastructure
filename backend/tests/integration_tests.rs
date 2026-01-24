use actix_http;
use actix_web::{http, test, web, App};
use dotenv::dotenv;
use key_infrastructure::auth::{LoginRequest, RegisterRequest};
use key_infrastructure::http_app;
use key_infrastructure::*;
use log::LevelFilter;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::env;

async fn setup_test_app() -> (
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    Pool<Postgres>,
) {
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .is_test(true)
        .try_init();
    dotenv().ok();
    // If DATABASE_URL is not set, try loading it from .test-env
    if env::var("DATABASE_URL").is_err() {
        dotenv::from_filename(".test-env").ok();
    }
    let database_url = env::var("DATABASE_URL").expect(
        "DATABASE_URL must be set for tests. Provide it in the environment or a .test-env file.",
    );
    log::info!("Connecting to {}", database_url);
    let jwt_secret = "test_secret".to_string();

    let pool = PgPoolOptions::new()
        .max_connections(2) // Use a single connection for tests to ensure isolation
        .connect(&database_url)
        .await
        .expect("Failed to create Postgres connection pool for tests");

    // Set up the database schema in a block to ensure the connection is released
    {
        let mut conn = pool
            .acquire()
            .await
            .expect("Failed to acquire connection from pool");

        // Not all postgres users have permission to create extensions. This might fail.
        // It's better to ensure the extension is created by a superuser beforehand.
        // However, for a local test setup, this is often fine.
        sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            .execute(&mut *conn)
            .await
            .ok(); // Use .ok() to ignore errors if the user doesn't have permission
        sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
            .execute(&mut *conn)
            .await
            .ok();

        log::info!("Clearing test tables");
        // Delete in reverse dependency order to avoid foreign key constraint issues
        sqlx::query("DELETE FROM revoked_certificates")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM private_keys")
            .execute(&mut *conn)
            .await
            .unwrap();
        // certificates must be deleted before certificate_requests because
        // certificates.id references certificate_requests(id) without ON DELETE CASCADE
        sqlx::query("DELETE FROM certificates")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM certificate_requests")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users")
            .execute(&mut *conn)
            .await
            .unwrap();
        log::info!("Tables cleared");
    }

    let app_state = web::Data::new(AppState {
        pool: pool.clone(),
        jwt_secret,
    });

    let app =
        test::init_service(App::new().configure(http_app::config_app(app_state.clone()))).await;

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
        role: None,
    };
    let req = test::TestRequest::post()
        .uri("/users")
        .set_json(&register_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::CREATED,
        "AUTH-01 Failed: Successful registration"
    );

    // AUTH-02: Attempt to register with an existing username
    let req = test::TestRequest::post()
        .uri("/users")
        .set_json(&register_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::CONFLICT,
        "AUTH-02 Failed: Duplicate username registration"
    );

    // AUTH-04: Log in with correct credentials
    let login_req = LoginRequest {
        username: "testuser".to_string(),
        password: "password123".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "AUTH-04 Failed: Successful login"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["token"].as_str().is_some(),
        "AUTH-04 Failed: Token not found in response"
    );

    // AUTH-05: Log in with an incorrect password
    let wrong_pass_req = LoginRequest {
        username: "testuser".to_string(),
        password: "wrongpassword".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&wrong_pass_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::UNAUTHORIZED,
        "AUTH-05 Failed: Incorrect password login"
    );

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
        role: None,
    };
    let req = test::TestRequest::post()
        .uri("/users")
        .set_json(&register_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::CREATED,
        "AUTH-01 Failed: Successful registration"
    );

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
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "AUTH-04 Failed: Successful login"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["token"].as_str().is_some(),
        "AUTH-04 Failed: Token not found in response"
    );
    let user = &body["user"];
    assert_eq!(
        user["role"].as_str().unwrap(),
        "ADMIN",
        "User should be logged in as admin"
    );
}

#[actix_web::test]
async fn test_certificate_lifecycle() {
    let (app, pool) = setup_test_app().await;
    let mut tx: sqlx::Transaction<'_, Postgres> = pool.begin().await.unwrap();
    let admin_user = "adminuser";
    let admin_password = "adminpass";
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
        role: None,
    };
    let req = test::TestRequest::post()
        .uri("/users")
        .set_json(&register_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::CREATED,
        "Failed to register user for cert test"
    );
    let user_body: serde_json::Value = test::read_body_json(resp).await;
    let user_id = user_body["id"].as_str().unwrap();

    // 2. Admin logs in
    let login_req = LoginRequest {
        username: admin_user.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "Admin login failed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let admin_token = body["token"].as_str().unwrap();
    assert_eq!(
        body["user"]["role"].as_str().unwrap(),
        "ADMIN",
        "Admin should be logged in as admin"
    );

    // 3. CERT-01: Admin creates a certificate request for the user
    let create_cert_req = json!({
        "dn": "CN=certuser/O=org/C=PL",
        "days_valid": 365,
    });
    let create_uri = format!("/users/{}/certificates/request", user_id);
    let req = test::TestRequest::post()
        .uri(&create_uri)
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&create_cert_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::CREATED,
        "CERT-01 Failed: Certificate request creation"
    );
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
    assert_eq!(
        user_login_body["user"]["role"].as_str().unwrap(),
        "USER",
        "User should be logged in as a USER"
    );

    // 5. CERT-03: User get list of available certificate requests
    let pending_uri = format!("/users/{}/certificates/pending", user_id);
    let req = test::TestRequest::get()
        .uri(&pending_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-03 Failed: Get certificate requests"
    );
    let list_body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        list_body["certificates"].is_array(),
        "CERT-03 Failed: Certificates should be array"
    );
    let certs = list_body["certificates"].as_array().unwrap();
    assert_eq!(
        certs.len(),
        1,
        "CERT-03 Failed: Should have one certificate request"
    );
    let cert = &certs[0];
    assert_eq!(
        cert["dn"].as_str().unwrap(),
        "CN=certuser/O=org/C=PL",
        "CERT-03 Failed: DN mismatch"
    );
    assert!(cert["valid_days"].as_i64().unwrap() > 0);
    assert_eq!(cert["id"].as_str().unwrap(), cert_id);

    // 6. CERT-04: User generate certificate
    let generate_req = json!({});
    let generate_uri = format!("/users/{}/certificates/{}/generate", user_id, cert_id);
    let req = test::TestRequest::post()
        .uri(&generate_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .set_json(&generate_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-04 Failed: Generate certificate"
    );

    // 7. CERT-05: User downloads their certificate (PKCS12) with the correct password
    let download_req = json!({ "password": test_password });
    let download_uri = format!("/users/{}/certificates/{}/pkcs12", user_id, cert_id);
    let req = test::TestRequest::post()
        .uri(&download_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .set_json(&download_req)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-05 Failed: PKCS12 download with correct password"
    );

    let content_type = resp.headers().get(http::header::CONTENT_TYPE).unwrap();
    assert!(
        content_type
            .to_str()
            .unwrap()
            .contains("application/octet-stream"),
        "CERT-05 Failed: Incorrect content type for PKCS12"
    );
    let content_disposition = resp
        .headers()
        .get(http::header::CONTENT_DISPOSITION)
        .unwrap();
    assert!(
        content_disposition.to_str().unwrap().contains(".p12"),
        "CERT-05 Failed: Incorrect file extension for PKCS12"
    );

    let body_bytes = test::read_body(resp).await;
    assert!(
        !body_bytes.is_empty(),
        "CERT-05 Failed: Downloaded PKCS12 file is empty"
    );

    // 8. CERT-05-PUB: User downloads public certificate (GET)
    let download_pub_uri = format!("/users/{}/certificates/{}/download", user_id, cert_id);
    let req = test::TestRequest::get()
        .uri(&download_pub_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-05-PUB Failed: Public certificate download"
    );

    let content_type = resp.headers().get(http::header::CONTENT_TYPE).unwrap();
    assert!(
        content_type
            .to_str()
            .unwrap()
            .contains("application/x-x509-ca-cert"),
        "CERT-05-PUB Failed: Incorrect content type for CRT"
    );
    let content_disposition = resp
        .headers()
        .get(http::header::CONTENT_DISPOSITION)
        .unwrap();
    assert!(
        content_disposition.to_str().unwrap().contains(".crt"),
        "CERT-05-PUB Failed: Incorrect file extension for CRT"
    );
}

#[actix_web::test]
async fn test_certificate_expiring_list() {
    let (app, pool) = setup_test_app().await;
    let mut tx = pool.begin().await.unwrap();

    // 1. Create admin user
    let admin_user = "expiring_admin";
    let admin_password = "adminpassword";
    let password_hash = bcrypt::hash(admin_password, 12).unwrap();
    sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'ADMIN')")
        .bind(admin_user)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 2. Create two regular users
    let regular_user_1 = "expiring_user_1";
    let regular_password_1 = "userpassword1";
    let user_id_1: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'USER') RETURNING id",
    )
    .bind(regular_user_1)
    .bind(bcrypt::hash(regular_password_1, 12).unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    let regular_user_2 = "expiring_user_2";
    let regular_password_2 = "userpassword2";
    let user_id_2: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'USER') RETURNING id",
    )
    .bind(regular_user_2)
    .bind(bcrypt::hash(regular_password_2, 12).unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    // 3. Create three certificates with different expiration dates for different users
    let now = chrono::Utc::now();

    // Cert 1 (User 1, expires in 15 days)
    let cert_id_1 = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO certificate_requests (id, user_id, dn, validity_period_days) VALUES ($1, $2, 'CN=user1_expiring15', 15)")
        .bind(cert_id_1)
        .bind(user_id_1)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO certificates (id, user_id, serial_number, status, expiration_date) VALUES ($1, $2, 'SN1', 'ACTIVE', $3)")
        .bind(cert_id_1)
        .bind(user_id_1)
        .bind(now + chrono::Duration::days(15))
        .execute(&mut *tx)
        .await
        .unwrap();

    // Cert 2 (User 2, expires in 20 days)
    let cert_id_2 = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO certificate_requests (id, user_id, dn, validity_period_days) VALUES ($1, $2, 'CN=user2_expiring20', 20)")
        .bind(cert_id_2)
        .bind(user_id_2)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO certificates (id, user_id, serial_number, status, expiration_date) VALUES ($1, $2, 'SN2', 'ACTIVE', $3)")
        .bind(cert_id_2)
        .bind(user_id_2)
        .bind(now + chrono::Duration::days(20))
        .execute(&mut *tx)
        .await
        .unwrap();

    // Cert 3 (User 1, expires in 45 days)
    let cert_id_3 = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO certificate_requests (id, user_id, dn, validity_period_days) VALUES ($1, $2, 'CN=user1_expiring45', 45)")
        .bind(cert_id_3)
        .bind(user_id_1)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO certificates (id, user_id, serial_number, status, expiration_date) VALUES ($1, $2, 'SN3', 'ACTIVE', $3)")
        .bind(cert_id_3)
        .bind(user_id_1)
        .bind(now + chrono::Duration::days(45))
        .execute(&mut *tx)
        .await
        .unwrap();

    tx.commit().await.unwrap();

    // 4. Admin logs in
    let login_req = LoginRequest {
        username: admin_user.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "Admin login failed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let admin_token = body["token"].as_str().unwrap();

    // 5. Admin calls /certificates/expiring?days=30 and should see 2 certs
    let req = test::TestRequest::get()
        .uri(&format!(
            "/users/{}/certificates/expiring?days=30",
            user_id_1
        )) // Note: This test logic might need review as API is scoped to user, but updating path to match route structure
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-09 Admin Failed: Could not get expiring certificates"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["total"], 1,
        "CERT-09 Admin Failed: Should be one expiring certificate"
    );
    let certs = body["certificates"].as_array().unwrap();
    assert_eq!(
        certs.len(),
        1,
        "CERT-09 Admin Failed: Certificate list should have one item"
    );
    assert_eq!(certs[0]["serialNumber"], "SN1");

    // 6. Admin calls with larger days value to get all 3
    let req_large = test::TestRequest::get()
        .uri(&format!(
            "/users/{}/certificates/expiring?days=50",
            user_id_1
        ))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();
    let resp_large = test::call_service(&app, req_large).await;
    assert_eq!(
        resp_large.status(),
        http::StatusCode::OK,
        "CERT-09 Admin Failed: Could not get expiring certificates with larger days value"
    );
    let body_large: serde_json::Value = test::read_body_json(resp_large).await;
    assert_eq!(
        body_large["total"], 2,
        "CERT-09 Admin Failed: Should be two expiring certificates for 50 days"
    );

    // 7. Test as non-admin user (user 1)
    let user_login_req = LoginRequest {
        username: regular_user_1.to_string(),
        password: regular_password_1.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&user_login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "User 1 login failed for expiring cert test"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let user_token = body["token"].as_str().unwrap();

    // 8. User 1 calls /certificates/expiring?days=30, should see only their own cert (1 cert)
    let req_user = test::TestRequest::get()
        .uri(&format!(
            "/users/{}/certificates/expiring?days=30",
            user_id_1
        ))
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .to_request();
    let resp_user = test::call_service(&app, req_user).await;
    assert_eq!(
        resp_user.status(),
        http::StatusCode::OK,
        "CERT-09 User Failed: Could not get expiring certificates"
    );
    let user_body: serde_json::Value = test::read_body_json(resp_user).await;
    assert_eq!(
        user_body["total"], 1,
        "CERT-09 User Failed: Should see only one of their own expiring certificates"
    );
    let user_certs = user_body["certificates"].as_array().unwrap();
    assert_eq!(user_certs.len(), 1);
    assert_eq!(user_certs[0]["serialNumber"], "SN1");
}

#[actix_web::test]
async fn test_certificate_revoke_admin() {
    // CERT-10: Administrator revokes a certificate using PUT /certificates/{id}/revoke with a reason
    let (app, pool) = setup_test_app().await;
    let mut tx = pool.begin().await.unwrap();

    // 1. Create admin user
    let admin_user = "revoke_admin";
    let admin_password = "adminpassword";
    let password_hash = bcrypt::hash(admin_password, 12).unwrap();
    sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'ADMIN')")
        .bind(admin_user)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 2. Create a regular user
    let regular_user = "revoke_user";
    let regular_password = "userpassword";
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'USER') RETURNING id",
    )
    .bind(regular_user)
    .bind(bcrypt::hash(regular_password, 12).unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    // 3. Create a certificate request and certificate
    let cert_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO certificate_requests (id, user_id, dn, validity_period_days) VALUES ($1, $2, 'CN=revoke_test', 365)")
        .bind(cert_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .unwrap();

    let now = chrono::Utc::now();
    sqlx::query("INSERT INTO certificates (id, user_id, serial_number, status, expiration_date) VALUES ($1, $2, 'SN_REVOKE_TEST', 'ACTIVE', $3)")
        .bind(cert_id)
        .bind(user_id)
        .bind(now + chrono::Duration::days(365))
        .execute(&mut *tx)
        .await
        .unwrap();

    tx.commit().await.unwrap();

    // 4. Admin logs in
    let login_req = LoginRequest {
        username: admin_user.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-10 Failed: Admin login failed"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let admin_token = body["token"].as_str().unwrap();

    // 5. Admin revokes the certificate
    let revoke_req = json!({
        "reason": "Security breach"
    });
    let revoke_uri = format!("/users/{}/certificates/{}/revoke", user_id, cert_id);
    let req = test::TestRequest::put()
        .uri(&revoke_uri)
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&revoke_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-10 Failed: Certificate revocation failed"
    );

    let revoke_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        revoke_body["id"].as_str().unwrap(),
        cert_id.to_string(),
        "CERT-10 Failed: Certificate ID mismatch"
    );
    assert_eq!(
        revoke_body["status"].as_str().unwrap(),
        "REVOKED",
        "CERT-10 Failed: Certificate status should be REVOKED"
    );
    assert!(
        revoke_body["revocation_date"].as_str().is_some(),
        "CERT-10 Failed: revocation_date should be set"
    );

    // 6. Verify certificate status in database
    let cert_status: String =
        sqlx::query_scalar("SELECT status::text FROM certificates WHERE id = $1")
            .bind(cert_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        cert_status, "REVOKED",
        "CERT-10 Failed: Certificate status in database should be REVOKED"
    );

    // 7. Verify certificate is recorded in revoked_certificates table
    let revoked_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM revoked_certificates WHERE certificate_id = $1")
            .bind(cert_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        revoked_count, 1,
        "CERT-10 Failed: Certificate should be recorded in revoked_certificates table"
    );

    // 8. Verify revocation reason is stored
    let revocation_reason: Option<String> =
        sqlx::query_scalar("SELECT reason FROM revoked_certificates WHERE certificate_id = $1")
            .bind(cert_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        revocation_reason,
        Some("Security breach".to_string()),
        "CERT-10 Failed: Revocation reason should be stored"
    );
}

#[actix_web::test]
async fn test_certificate_revoke_regular_user() {
    // CERT-11: A regular user attempts to revoke a certificate
    let (app, pool) = setup_test_app().await;
    let mut tx = pool.begin().await.unwrap();

    // 1. Create admin user
    let admin_user = "revoke_admin2";
    let admin_password = "adminpassword";
    let password_hash = bcrypt::hash(admin_password, 12).unwrap();
    sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'ADMIN')")
        .bind(admin_user)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 2. Create a victim user
    let victim_user = "revoke_victim";
    let victim_password = "userpassword";
    let victim_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'USER') RETURNING id",
    )
    .bind(victim_user)
    .bind(bcrypt::hash(victim_password, 12).unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    // 3. Create a certificate request and certificate
    let cert_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO certificate_requests (id, user_id, dn, validity_period_days) VALUES ($1, $2, 'CN=revoke_test_victim', 365)")
        .bind(cert_id)
        .bind(victim_id)
        .execute(&mut *tx)
        .await
        .unwrap();

    let now = chrono::Utc::now();
    sqlx::query("INSERT INTO certificates (id, user_id, serial_number, status, expiration_date) VALUES ($1, $2, 'SN_REVOKE_TEST_VICTIM', 'ACTIVE', $3)")
        .bind(cert_id)
        .bind(victim_id)
        .bind(now + chrono::Duration::days(365))
        .execute(&mut *tx)
        .await
        .unwrap();

    // 4. Create an attacker user
    let attacker_user = "revoke_attacker";
    let attacker_password = "userpassword";
    let _attacker_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'USER') RETURNING id",
    )
    .bind(attacker_user)
    .bind(bcrypt::hash(attacker_password, 12).unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    // 5. Attacker logs in
    let login_req = LoginRequest {
        username: attacker_user.to_string(),
        password: attacker_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-11 Failed: Attacker login failed"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let attacker_token = body["token"].as_str().unwrap();

    // 6. Attacker attempts to revoke the victim's certificate
    let revoke_req = json!({
        "reason": "Test revocation"
    });
    let revoke_uri = format!("/users/{}/certificates/{}/revoke", victim_id, cert_id);
    let req = test::TestRequest::put()
        .uri(&revoke_uri)
        .insert_header(("Authorization", format!("Bearer {}", attacker_token)))
        .set_json(&revoke_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::FORBIDDEN,
        "CERT-11 Failed: Regular user should not be able to revoke certificate"
    );

    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap_or("");
    if !body_str.is_empty() {
        assert!(
            body_str.contains("Admin access required")
                || body_str.contains("Forbidden")
                || body_str.contains("Insufficient permissions"),
            "CERT-11 Failed: Error message should indicate admin access required. Got: {}",
            body_str
        );
    }

    // 6. Verify certificate status is still ACTIVE in database
    let cert_status: String =
        sqlx::query_scalar("SELECT status::text FROM certificates WHERE id = $1")
            .bind(cert_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        cert_status, "ACTIVE",
        "CERT-11 Failed: Certificate status should remain ACTIVE"
    );
}

#[actix_web::test]
async fn test_certificate_revoke_not_found() {
    // CERT-12: Attempt to revoke a non-existent certificate
    let (app, pool) = setup_test_app().await;
    let mut tx = pool.begin().await.unwrap();

    // 1. Create admin user
    let admin_user = "revoke_admin3";
    let admin_password = "adminpassword";
    let password_hash = bcrypt::hash(admin_password, 12).unwrap();
    sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'ADMIN')")
        .bind(admin_user)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .unwrap();

    tx.commit().await.unwrap();

    // 2. Admin logs in
    let login_req = LoginRequest {
        username: admin_user.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "CERT-12 Failed: Admin login failed"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let admin_token = body["token"].as_str().unwrap();

    // 3. Admin attempts to revoke a non-existent certificate
    let non_existent_cert_id = uuid::Uuid::new_v4();
    let revoke_req = json!({
        "reason": "Test revocation"
    });
    let revoke_uri = format!(
        "/users/{}/certificates/{}/revoke",
        uuid::Uuid::new_v4(),
        non_existent_cert_id
    );
    let req = test::TestRequest::put()
        .uri(&revoke_uri)
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&revoke_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::NOT_FOUND,
        "CERT-12 Failed: Should return 404 for non-existent certificate"
    );

    let error_body: serde_json::Value = test::read_body_json(resp).await;
    // The error response is a JSON string, not an object with a "message" field
    // Handle both string responses and object responses
    let error_message = match &error_body {
        serde_json::Value::String(s) => s.as_str(),
        _ => error_body["message"]
            .as_str()
            .or_else(|| error_body["error"].as_str())
            .unwrap_or(""),
    };
    assert!(
        error_message.contains("Certificate not found") || error_message.contains("not found"),
        "CERT-12 Failed: Error message should indicate certificate not found. Got: {:?}",
        error_body
    );
}

#[actix_web::test]
async fn test_admin_download_user_certificate() {
    let (app, pool) = setup_test_app().await;
    let mut tx = pool.begin().await.unwrap();

    // 1. Create admin user
    let admin_user = "dl_admin";
    let admin_password = "adminpassword";
    let password_hash = bcrypt::hash(admin_password, 12).unwrap();
    sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'ADMIN')")
        .bind(admin_user)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 2. Create regular user
    let regular_user = "dl_user";
    let regular_password = "userpassword";
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'USER') RETURNING id",
    )
    .bind(regular_user)
    .bind(bcrypt::hash(regular_password, 12).unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    // 3. Admin logs in
    let login_req = LoginRequest {
        username: admin_user.to_string(),
        password: admin_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "Admin login failed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let admin_token = body["token"].as_str().unwrap();

    // 4. Admin creates certificate request
    let create_cert_req = json!({
        "dn": "CN=dl_test",
        "days_valid": 365,
    });
    let create_uri = format!("/users/{}/certificates/request", user_id);
    let req = test::TestRequest::post()
        .uri(&create_uri)
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&create_cert_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), http::StatusCode::CREATED);
    let cert_body: serde_json::Value = test::read_body_json(resp).await;
    let cert_id = cert_body["id"].as_str().unwrap();

    // 5. User logs in to generate certificate
    let user_login_req = LoginRequest {
        username: regular_user.to_string(),
        password: regular_password.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&user_login_req)
        .to_request();
    let resp = test::call_service(&app, req).await;
    let user_body: serde_json::Value = test::read_body_json(resp).await;
    let user_token = user_body["token"].as_str().unwrap();

    // 6. User generates certificate
    let generate_uri = format!("/users/{}/certificates/{}/generate", user_id, cert_id);
    let req = test::TestRequest::post()
        .uri(&generate_uri)
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .set_json(&json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "Failed to generate certificate"
    );

    // 7. Admin downloads user's certificate
    let download_uri = format!("/users/{}/certificates/{}/download", user_id, cert_id);
    let req = test::TestRequest::get()
        .uri(&download_uri)
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "Admin failed to download user certificate"
    );

    let content_type = resp.headers().get(http::header::CONTENT_TYPE).unwrap();
    assert!(
        content_type
            .to_str()
            .unwrap()
            .contains("application/x-x509-ca-cert"),
        "Incorrect content type"
    );
    let content_disposition = resp
        .headers()
        .get(http::header::CONTENT_DISPOSITION)
        .unwrap();
    assert!(
        content_disposition.to_str().unwrap().contains(".crt"),
        "Incorrect file extension"
    );
}
