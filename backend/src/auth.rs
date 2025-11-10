use actix_web::{cookie::{Cookie, SameSite}, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
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

    log::info!("Login attempt for user: {}", username);

    let user = match sqlx::query_as::<_, User>("SELECT id, username, password_hash, role FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(Some(user)) => {
            log::info!("Found user {}, id: {}, role: {}", user.username, user.id, user.role.to_string());
            user
        },
        Ok(None) => {
            log::warn!("Login failed: user '{}' not found", username);
            return HttpResponse::Unauthorized().body("Invalid credentials");
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
            log::info!("Returning token: {}", token);

            let cookie = Cookie::build("auth_token", token.clone())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                // The cookie will expire when the token does
                .max_age(actix_web::cookie::time::Duration::hours(1)) 
                .finish();

            HttpResponse::Ok()
                .cookie(cookie)
                .json(LoginResponse { token, user: user_info })
        },
        Ok(false) => {
            log::warn!("Login failed (bad password) for user '{}'", username);
            HttpResponse::Unauthorized().body("Invalid credentials")
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
    let pin = req.pin.clone();

    // Log registration attempt (do NOT log the password!)
    log::info!("Registration attempt for user: {}", username);

    // Validate PIN length
    if pin.len() < 8 {
        log::warn!("Registration failed for user '{}': PIN is too short", username);
        return HttpResponse::BadRequest().body("PIN must be at least 8 characters long");
    }

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
    // The `pin` is not stored directly. It's used to encrypt private keys when created.
    // We will set a default role of 'USER' and return the newly created user.
    match sqlx::query_as::<_, User>("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, password_hash, role")
        .bind(&username)
        .bind(&password_hash)
        .bind(UserRole::USER) // Set default role
        .fetch_one(&state.pool)
        .await
    {
        Ok(new_user) => {
            log::info!("Registration successful for user '{}'", new_user.username);
            let ui = UserInfo{
                username: new_user.username,
                id: new_user.id.to_string(),
                role: new_user.role.to_string(),
            };
            HttpResponse::Created().json(ui)
        },
        Err(_) => {
            log::error!("Failed to insert new user '{}' during registration", username);
            HttpResponse::InternalServerError().finish()
        },
    }
}
