use actix_web::{
    cookie::{Cookie, SameSite},
    web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::db_model::{User, UserRole};
use crate::AppState;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Deserialize, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
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
    created_at: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    valid: bool,
    role: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    username: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String, //user login password
    pub role: Option<UserRole>,
}

pub async fn login(state: web::Data<AppState>, req: web::Json<LoginRequest>) -> impl Responder {
    let username = req.username.clone();
    let password = req.password.clone();

    log::info!("Login attempt for user: {}", username);

    let user = match sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(user)) => {
            log::info!(
                "Found user {}, id: {}, role: {}",
                user.username,
                user.id,
                user.role
            );
            user
        }
        Ok(None) => {
            log::warn!("Login failed: user '{}' not found", username);
            return HttpResponse::Unauthorized().body("Invalid credentials");
        }
        Err(_) => {
            log::error!("Database error on login attempt for user: {}", username);
            return HttpResponse::InternalServerError().finish();
        }
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
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.jwt_secret.as_ref()),
            )
            .unwrap();

            let user_info = UserInfo {
                id: user.id.to_string(),
                username: user.username,
                role: user.role.to_string(),
                created_at: user.created_at.to_rfc3339(),
            };
            log::info!("Returning token: {}", token);

            let cookie = Cookie::build("auth_token", token.clone())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                // The cookie will expire when the token does
                .max_age(actix_web::cookie::time::Duration::hours(1))
                .finish();

            HttpResponse::Ok().cookie(cookie).json(LoginResponse {
                token,
                user: user_info,
            })
        }
        Ok(false) => {
            log::warn!("Login failed (bad password) for user '{}'", username);
            HttpResponse::Unauthorized().body("Invalid credentials")
        }
        Err(_) => {
            log::error!("Password verification failed for user: {}", username);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn verify_token(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let auth_header = req.headers().get("Authorization");

    let token = match auth_header {
        Some(value) => {
            let parts: Vec<&str> = value.to_str().unwrap_or("").split_whitespace().collect();
            if parts.len() == 2 && parts[0] == "Bearer" {
                Some(parts[1].to_string())
            } else {
                None
            }
        }
        None => None,
    };

    let token = match token {
        Some(t) => t,
        None => {
            log::warn!("Verify token failed: No Authorization header or malformed token");
            return HttpResponse::Ok().json(VerifyResponse {
                valid: false,
                role: None,
                user_id: None,
                username: None,
            });
        }
    };
    log::info!("Verifying token: {}", token);

    let decoding_key = DecodingKey::from_secret(state.jwt_secret.as_ref());
    let validation = Validation::default();

    match decode::<Claims>(&token, &decoding_key, &validation) {
        Ok(token_data) => {
            log::info!(
                "Token valid for user: {}, role: {}",
                token_data.claims.sub,
                token_data.claims.role
            );

            // Fetch username from database
            let username =
                match sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = $1")
                    .bind(uuid::Uuid::parse_str(&token_data.claims.sub).ok())
                    .fetch_optional(&state.pool)
                    .await
                {
                    Ok(Some(name)) => Some(name),
                    Ok(None) => {
                        log::warn!("User not found for id: {}", token_data.claims.sub);
                        None
                    }
                    Err(e) => {
                        log::error!("Database error fetching username: {:?}", e);
                        None
                    }
                };

            HttpResponse::Ok().json(VerifyResponse {
                valid: true,
                role: Some(token_data.claims.role),
                user_id: Some(token_data.claims.sub),
                username,
            })
        }
        Err(e) => {
            log::warn!("Token verification failed: {:?}", e);
            HttpResponse::Ok().json(VerifyResponse {
                valid: false,
                role: None,
                user_id: None,
                username: None,
            })
        }
    }
}

pub async fn register(
    state: web::Data<AppState>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    let username = req.username.clone();
    let password = req.password.clone();

    // Log registration attempt (do NOT log the password!)
    log::info!("Registration attempt for user: {}", username);

    // Check if user already exists
    let exists = match sqlx::query("SELECT 1 FROM users WHERE username = $1 LIMIT 1")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            log::error!("Database error while checking if user exists: {:?}", e);
            e
        }) {
        Ok(opt) => opt.is_some(),
        Err(_) => {
            log::error!("Database error during registration for user: {}", username);
            return HttpResponse::InternalServerError().finish();
        }
    };

    if exists {
        log::warn!("Registration failed: user '{}' already exists", username);
        return HttpResponse::Conflict().body("Username already exists");
    }

    // Hash password with bcrypt
    let password_hash = match hash(&password, 12) {
        Ok(h) => h,
        Err(_) => {
            log::error!(
                "Password hash failed during registration for user: {}",
                username
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Insert new user
    log::debug!("Insert new user: {}", username);
    // Password will be used to encrypt private keys when certificates are created.
    // Use the role from the request, defaulting to 'USER' if not provided.
    let user_role = req.role.clone().unwrap_or(UserRole::USER);
    match sqlx::query_as::<_, User>("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, password_hash, role, created_at")
        .bind(&username)
        .bind(&password_hash)
        .bind(user_role)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            log::error!("Database error while inserting new user: {:?}", e);
            e
        })
    {
        Ok(new_user) => {
            log::info!("Registration successful for user '{}'", new_user.username);
            let ui = UserInfo{
                username: new_user.username,
                id: new_user.id.to_string(),
                role: new_user.role.to_string(),
                created_at: new_user.created_at.to_rfc3339(),
            };
            HttpResponse::Created().json(ui)
        },
        Err(_) => {
            log::error!("Failed to insert new user '{}' during registration", username);
            HttpResponse::InternalServerError().finish()
        },
    }
}

pub async fn logout() -> impl Responder {
    log::info!("Logout request received");

    // Create a cookie with the same attributes as the login cookie, but with max_age set to 0 to delete it
    let cookie = Cookie::build("auth_token", "")
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "message": "Logged out successfully" }))
}

pub async fn list_users(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    // 1. Extract claims inserted by the JWT middleware.
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => {
            // This case should ideally not be reached if middleware is applied correctly.
            log::warn!("list_users endpoint reached without claims.");
            return HttpResponse::Unauthorized().json("Not authenticated.");
        }
    };

    // 2. Check if the user has the ADMIN role.
    if claims.role != UserRole::ADMIN.to_string() {
        log::warn!(
            "User '{}' with role '{}' attempted to access list_users.",
            claims.sub,
            claims.role
        );
        return HttpResponse::Forbidden()
            .json("Insufficient permissions. Administrator role required.");
    }

    log::info!("Admin user '{}' is listing all users.", claims.sub);

    // 3. Fetch all users from the database.
    match sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, role, created_at FROM users",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(users) => {
            // 4. Map the full User struct to the public UserInfo struct.
            let user_infos: Vec<UserInfo> = users
                .into_iter()
                .map(|user| UserInfo {
                    id: user.id.to_string(),
                    username: user.username,
                    role: user.role.to_string(),
                    created_at: user.created_at.to_rfc3339(),
                })
                .collect();
            HttpResponse::Ok().json(user_infos)
        }
        Err(e) => {
            log::error!("Failed to fetch users from database: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to retrieve users.")
        }
    }
}
