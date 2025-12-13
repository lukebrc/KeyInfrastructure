use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type, Postgres, Pool};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Type, Clone, Copy, PartialEq, Eq)]
#[sqlx(type_name = "user_role", rename_all = "UPPERCASE")]
pub enum UserRole {
    USER,
    ADMIN,
}

impl ToString for UserRole {
    fn to_string(&self) -> String {
        match self {
            UserRole::USER => "USER".to_string(),
            UserRole::ADMIN => "ADMIN".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Type, Clone, Copy, PartialEq, Eq)]
#[sqlx(type_name = "certificate_status", rename_all = "UPPERCASE")]
pub enum CertificateStatus {
    ACTIVE,
    EXPIRED,
    REVOKED,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub id: Uuid,
    pub serial_number: String,
    pub dn: String,
    pub status: CertificateStatus,
    pub expiration_date: DateTime<Utc>,
    pub renewed_count: i32,
    pub certificate_der: Vec<u8>,
    pub renewal_date: Option<DateTime<Utc>>
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct CertificateListItem {
    pub id: Uuid,
    pub serial_number: String,
    pub dn: String,
    pub status: CertificateStatus,
    pub expiration_date: DateTime<Utc>,
    pub renewed_count: i32,
}



pub struct AppState {
    pub pool: Pool<Postgres>,
    pub jwt_secret: String,
}
