use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use bcrypt::{hash, verify};
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use crate::AppState;
use crate::db_model::{User, UserRole};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String,
    user: UserInfo,
}

#[derive(Serialize)]
pub struct UserInfo {
    id: String,
    username: String,
    role: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
    pin: String, // Must be exactly 8 characters, should be validated before insert
}

pub async fn login(state: web::Data<AppState>, req: web::Json<LoginRequest>) -> impl Responder {
    let username = req.username.clone();
    let password = req.password.clone();

    // Log login attempt (do NOT log the password!)
    log::info!("Login attempt for user: {}", username);

    let user = match sqlx::query_as::<_, User>("SELECT id, username, password_hash, role FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            log::warn!("Login failed: user '{}' not found", username);
            return HttpResponse::Unauthorized().finish();
        }
        Err(_) => {
            log::error!("Database error on login attempt for user: {}", username);
            return HttpResponse::InternalServerError().finish();
        },
    };

    match verify(&password, &user.password_hash) {
        Ok(true) => {
            log::info!("Login successful for user '{}'", username);
            let exp = (Utc::now() + Duration::hours(1)).timestamp() as usize;
            let claims = Claims {
                sub: user.id.to_string(),
                role: user.role.to_string(),
                exp,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_ref())).unwrap();
            
            let user_info = UserInfo {
                id: user.id.to_string(),
                username: user.username,
                role: user.role.to_string(),
            };

            HttpResponse::Ok().json(LoginResponse {
                token,
                user: user_info,
            })
        },
        Ok(false) => {
            log::warn!("Login failed (bad password) for user '{}'", username);
            HttpResponse::Unauthorized().finish()
        },
        Err(_) => {
            log::error!("Password verification failed for user: {}", username);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn register(state: web::Data<AppState>, req: web::Json<RegisterRequest>) -> impl Responder {
    let username = req.username.clone();
    let password = req.password.clone();

    // Log registration attempt (do NOT log the password!)
    log::info!("Registration attempt for user: {}", username);

    // Check if user already exists
    let exists = match sqlx::query("SELECT 1 FROM users WHERE username = $1 LIMIT 1")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(opt) => opt.is_some(),
        Err(_) => {
            log::error!("Database error during registration for user: {}", username);
            return HttpResponse::InternalServerError().finish();
        },
    };

    if exists {
        log::warn!("Registration failed: user '{}' already exists", username);
        return HttpResponse::Conflict().body("Username already exists");
    }

    // Hash password with bcrypt
    let password_hash = match hash(&password, 12) {
        Ok(h) => h,
        Err(_) => {
            log::error!("Password hash failed during registration for user: {}", username);
            return HttpResponse::InternalServerError().finish();
        },
    };

    // Insert new user
    match sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(&username)
        .bind(&password_hash)
        .execute(&state.pool)
        .await
    {
        Ok(_) => {
            log::info!("Registration successful for user '{}'", username);
            HttpResponse::Created().finish()
        },
        Err(_) => {
            log::error!("Failed to insert new user '{}' during registration", username);
            HttpResponse::InternalServerError().finish()
        },
    }
}
