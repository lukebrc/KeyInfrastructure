use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::Row;
use argon2::{Argon2, password_hash::{PasswordHash, PasswordVerifier, PasswordHasher, SaltString}};
use rand_core::OsRng;

use crate::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    login: String,
    password: String,
}

pub async fn login(state: web::Data<AppState>, req: web::Json<LoginRequest>) -> impl Responder {
    let username = req.username.clone();
    let password = req.password.clone();

    let row = match sqlx::query("SELECT password_hash FROM users WHERE username = $1 LIMIT 1")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(r) => r,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let Some(row) = row else {
        return HttpResponse::Unauthorized().finish();
    };

    let password_hash: String = match row.try_get("password_hash") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let parsed_hash = match PasswordHash::new(&password_hash) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => HttpResponse::Ok().body("Login successful!"),
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

pub async fn register(state: web::Data<AppState>, req: web::Json<RegisterRequest>) -> impl Responder {
    let username = req.login.clone();
    let password = req.password.clone();

    // Check if user already exists
    let exists = match sqlx::query("SELECT 1 FROM users WHERE username = $1 LIMIT 1")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(opt) => opt.is_some(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if exists {
        return HttpResponse::Conflict().body("Username already exists");
    }

    // Hash password with Argon2
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Insert new user
    match sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(&username)
        .bind(&password_hash)
        .execute(&state.pool)
        .await
    {
        Ok(_) => HttpResponse::Created().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}


