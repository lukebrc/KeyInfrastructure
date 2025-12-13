use actix_web::{http::header, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use futures_util::TryFutureExt;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::symm::{decrypt, Cipher};
use openssl::x509::{X509, X509Builder, X509Name};
use openssl::rsa::Rsa;
use openssl::asn1::Asn1Time;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::fs;
use uuid::Uuid;

use crate::{
    auth::Claims,
    db_model::{CertificateInfo, CertificateListItem, CertificateStatus, User},
    errors::ApiError,
    AppState,
};

const RSA_KEY_SIZE: u32 = 2048;

#[derive(Deserialize, Debug)]
pub struct ListCertificatesQuery {
    page: Option<i64>,
    limit: Option<i64>,
    status: Option<String>,
    sort_by: Option<String>,
    order: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ListExpiringCertificatesQuery {
    days: Option<i64>,
    page: Option<i64>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct CreateCertificateRequest {
    dn: String,
    days_valid: i64,
}

#[derive(Deserialize)]
pub struct DownloadCertificateRequest {
    password: String,
}

#[derive(Deserialize)]
pub struct RevokeCertificateRequest {
    reason: Option<String>,
}

#[derive(Serialize)]
pub struct RevokeCertificateResponse {
    id: String,
    status: String,
    revocation_date: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct ListCertificatesResponse {
    certificates: Vec<CertificateListItem>,
    total: i64,
    page: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PendingCertificateInfo {
    pub id: Uuid,
    pub valid_days: i32,
    pub dn: String,
}

#[derive(Serialize)]
pub struct ListPendingCertificatesResponse {
    pub certificates: Vec<PendingCertificateInfo>,
}

#[derive(Serialize)]
pub struct CertificateCreatedResponse {
    id: String,
    user_id: String,
}

pub async fn create_certificate_request(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<CreateCertificateRequest>,
) -> Result<impl Responder, ApiError> {

    let user_id = path.into_inner();
    log::info!(
        "Attempting to create certificate for user_id: {}",
        user_id
    );
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    // Authorization: Only admins can create certificates.
    if claims.role != "ADMIN" {
        log::error!("user_id: {} is not Admin", user_id);
        return Err(ApiError::Forbidden(
            "Only admins can create certificates".to_string(),
        ));
    }

    // Fetch the user to get their hashed password for encryption
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    let days_valid = body.days_valid;
    log::info!(
        "Adding certificate request for user {} dn: {}, days_valid: {}",
        user_id,
        body.dn,
        days_valid
    );

    // Store certificate details in the database
    let new_cert_id: Uuid = sqlx::query_scalar(
        "INSERT INTO certificate_requests (user_id, dn, validity_period_days) VALUES ($1, $2, $3) RETURNING id"
    )
        .bind(user.id)
        .bind(&body.dn)
        .bind(days_valid)
        .fetch_one(&state.pool)
        .await?;

    log::info!(
        "Successfully created certificate request with id: {}",
        new_cert_id
    );
    let response = CertificateCreatedResponse {
        id: new_cert_id.to_string(),
        user_id: user.id.to_string(),
    };
    Ok(HttpResponse::Created().json(response))
}

pub async fn download_certificate(state: web::Data<AppState>,
            req: HttpRequest,
            path: web::Path<Uuid>,
            body: web::Json<DownloadCertificateRequest>,
        ) -> Result<impl Responder, ApiError> {

    let cert_id = path.into_inner();
    log::info!("Attempting to download certificate with id: {}", cert_id);

    let user = match get_authorized_user_data(req, &state.pool).await {
        Ok(u) => u,
        Err(err) => {
            log::error!("Cannot get user data: {}", err);
            return Err(err);
        }
    };

    // Verify password against the user's stored hash
    if !bcrypt::verify(&body.password, &user.password_hash)
        .map_err(|_| ApiError::Internal("password verification failed".to_string()))?
    {
        log::error!("Incorrect password for user {}", user.id);
        return Err(ApiError::BadRequest("Incorrect password".to_string()));
    }

    let pkcs_result = generate_user_pkcs12(cert_id, user, body.password.clone(), &state.pool).await;
    let pkcs12 = match pkcs_result {
        Ok(c) => c,
        Err(err) => {
            log::error!("Cannot get certificate with id={}: error: {}", cert_id, err);
            return Err(err);
        }
    };

    let filename = format!("attachment; filename=\"{}.p12\"", cert_id);
    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_DISPOSITION, filename))
        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
        .body(pkcs12))
}

pub async fn revoke_certificate(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<RevokeCertificateRequest>,
) -> Result<impl Responder, ApiError> {
    let cert_id = path.into_inner();
    log::info!("Attempting to revoke certificate with id: {}", cert_id);

    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    // Authorization: Only admins can revoke certificates
    if claims.role != "ADMIN" {
        log::error!("User {} is not Admin, cannot revoke certificate", claims.sub);
        return Err(ApiError::Forbidden("Admin access required".to_string()));
    }

    // Check if certificate exists
    let cert_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM certificates WHERE id = $1)")
        .bind(cert_id)
        .fetch_one(&state.pool)
        .await?;

    if !cert_exists {
        log::error!("Certificate with id {} not found", cert_id);
        return Err(ApiError::NotFound("Certificate not found".to_string()));
    }

    // Update certificate status to REVOKED
    sqlx::query("UPDATE certificates SET status = $1 WHERE id = $2")
        .bind(CertificateStatus::REVOKED)
        .bind(cert_id)
        .execute(&state.pool)
        .await?;

    // Insert into revoked_certificates table
    let revocation_date = Utc::now();
    sqlx::query("INSERT INTO revoked_certificates (certificate_id, revocation_date, reason) VALUES ($1, $2, $3) ON CONFLICT (certificate_id) DO UPDATE SET revocation_date = $2, reason = $3")
        .bind(cert_id)
        .bind(revocation_date)
        .bind(body.reason.as_deref())
        .execute(&state.pool)
        .await?;

    log::info!("Successfully revoked certificate with id: {}", cert_id);

    let response = RevokeCertificateResponse {
        id: cert_id.to_string(),
        status: "REVOKED".to_string(),
        revocation_date,
    };

    Ok(HttpResponse::Ok().json(response))
}

pub async fn list_active_certificates(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    query: web::Query<ListCertificatesQuery>,
) -> Result<impl Responder, ApiError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    let path_user_id = path.into_inner();
    let claims_user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::Internal("Invalid UUID in claims".into()))?;

    // Authorization: Admin can view any user's certificates, regular users can only view their own
    if claims.role != "ADMIN" && path_user_id != claims_user_id {
        return Err(ApiError::Forbidden(
            "You can only view your own certificates".to_string(),
        ));
    }

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    let sort_by = query.sort_by.as_deref().unwrap_or("expiration_date");
    let order = query.order.as_deref().unwrap_or("asc");
    log::info!(
        "Listing certificates for user {}, page {}, offset {}",
        path_user_id,
        page,
        offset
    );

    // Basic validation to prevent SQL injection
    let allowed_sort_columns = [
        "serial_number",
        "dn",
        "status",
        "expiration_date",
        "renewed_count",
    ];
    if !allowed_sort_columns.contains(&sort_by) {
        return Err(ApiError::BadRequest("Invalid sort_by parameter".into()));
    }
    let order_direction = if order.eq_ignore_ascii_case("desc") {
        "DESC"
    } else {
        "ASC"
    };

    let status_filter = query.status.as_deref();

    // Build query for total count
    let count_query = "SELECT COUNT(*) FROM certificates WHERE user_id = $1".to_string()
        + if status_filter.is_some() {
            " AND status = $2"
        } else {
            ""
        };

    let mut count_query_builder = sqlx::query_scalar(&count_query).bind(path_user_id);
    if let Some(status) = status_filter {
        count_query_builder = count_query_builder.bind(status);
    }

    let total: i64 = count_query_builder.fetch_one(&state.pool).await?;

    // Build query for fetching certificates with correct parameter indexing
    let status_clause = if status_filter.is_some() {
        "AND status = $2"
    } else {
        ""
    };
    let limit_offset_params = if status_filter.is_some() {
        "LIMIT $3 OFFSET $4"
    } else {
        "LIMIT $2 OFFSET $3"
    };

    let select_query = format!(
        "SELECT c.id, c.serial_number, cr.dn, c.status, c.expiration_date, c.renewed_count FROM certificates c JOIN certificate_requests cr ON c.id = cr.id WHERE c.user_id = $1 {} ORDER BY {} {} {}",
        status_clause,
        sort_by,
        order_direction,
        limit_offset_params
    );

    let mut query_builder = sqlx::query_as::<_, CertificateListItem>(&select_query).bind(path_user_id);

    if let Some(status) = status_filter {
        let cert_status: CertificateStatus = match status.to_uppercase().as_str() {
            "ACTIVE" => CertificateStatus::ACTIVE,
            "EXPIRED" => CertificateStatus::EXPIRED,
            "REVOKED" => CertificateStatus::REVOKED,
            _ => return Err(ApiError::BadRequest("Invalid status filter".into())),
        };
        query_builder = query_builder.bind(cert_status);
    }

    let query_builder = query_builder.bind(limit).bind(offset);
    let certificates = query_builder.fetch_all(&state.pool).await?;

    Ok(HttpResponse::Ok().json(ListCertificatesResponse {
        certificates,
        total,
        page,
    }))
}

pub async fn list_expiring_certificates(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<ListExpiringCertificatesQuery>,
) -> Result<impl Responder, ApiError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    let days = query.days.unwrap_or(30);
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    let now = Utc::now();
    let expiration_threshold = now + chrono::Duration::days(days);

    let (total, certificates): (i64, Vec<CertificateListItem>) = if claims.role == "ADMIN" {
        // Admin sees all expiring certificates
        let count_query = "SELECT COUNT(*) FROM certificates WHERE status = 'ACTIVE' AND expiration_date BETWEEN $1 AND $2";
        let total: i64 = sqlx::query_scalar(count_query)
            .bind(now)
            .bind(expiration_threshold)
            .fetch_one(&state.pool)
            .await?;

        let select_query = "SELECT c.id, c.serial_number, cr.dn, c.status, c.expiration_date, c.renewed_count FROM certificates c JOIN certificate_requests cr ON c.id = cr.id WHERE c.status = 'ACTIVE' AND c.expiration_date BETWEEN $1 AND $2 ORDER BY c.expiration_date ASC LIMIT $3 OFFSET $4";
        let certificates = sqlx::query_as::<_, CertificateListItem>(select_query)
            .bind(now)
            .bind(expiration_threshold)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await?;
        (total, certificates)
    } else {
        // Regular user sees only their own expiring certificates
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| ApiError::Internal("Invalid UUID in claims".into()))?;

        let count_query = "SELECT COUNT(*) FROM certificates WHERE user_id = $1 AND status = 'ACTIVE' AND expiration_date BETWEEN $2 AND $3";
        let total: i64 = sqlx::query_scalar(count_query)
            .bind(user_id)
            .bind(now)
            .bind(expiration_threshold)
            .fetch_one(&state.pool)
            .await?;

        let select_query = "SELECT c.id, c.serial_number, cr.dn, c.status, c.expiration_date, c.renewed_count FROM certificates c JOIN certificate_requests cr ON c.id = cr.id WHERE c.user_id = $1 AND c.status = 'ACTIVE' AND c.expiration_date BETWEEN $2 AND $3 ORDER BY c.expiration_date ASC LIMIT $4 OFFSET $5";
        let certificates = sqlx::query_as::<_, CertificateListItem>(select_query)
            .bind(user_id)
            .bind(now)
            .bind(expiration_threshold)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await?;
        (total, certificates)
    };

    Ok(HttpResponse::Ok().json(ListCertificatesResponse {
        certificates,
        total,
        page,
    }))
}

pub async fn list_pending_certificates(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<impl Responder, ApiError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    let path_user_id = path.into_inner();
    let claims_user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::Internal("Invalid UUID in claims".into()))?;

    // Authorization: Admin can view any user's certificates, regular users can only view their own
    if claims.role != "ADMIN" && path_user_id != claims_user_id {
        return Err(ApiError::Forbidden(
            "You can only view your own certificates".to_string(),
        ));
    }

    log::info!("Listing pending certificates for user {}", path_user_id);

    let rows = sqlx::query_as::<_, PendingCertificateInfo>(
        "SELECT cr.id, cr.validity_period_days as valid_days, cr.dn
            FROM certificate_requests cr
            WHERE cr.user_id = $1 AND accepted_at IS NULL",
    )
        .bind(path_user_id)
        .fetch_all(&state.pool)
        .await;

    match rows {
        Ok(certificates) => {
            log::info!("Returning {} pending certificates", certificates.len());
            Ok(HttpResponse::Ok().json(ListPendingCertificatesResponse { certificates }))
        }
        Err(err) => {
            log::error!("Could not get certificates {}", err);
            Ok(HttpResponse::InternalServerError().body(err.to_string()))
        }
    }
}

fn build_certificate(
    private_key: &PKey<Private>,
    pending_request: &PendingCertificateInfo,
    not_after: &Asn1Time,
) -> Result<(X509, String), ApiError> {
    use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier};
    use openssl::bn::BigNum;

    log::debug!("Building certificate for {}", pending_request.dn);
    // Build certificate
    let mut builder = X509Builder::new()
        .map_err(|e| ApiError::Internal(format!("X509Builder error: {}", e)))?;

    builder.set_pubkey(private_key)
        .map_err(|e| ApiError::Internal(format!("set_pubkey: {}", e)))?;

    // Load root CA certificate and private key from filesystem
    let ca_cert_pem = fs::read("ca/ca.crt")
        .map_err(|e| ApiError::Internal(format!("Failed to read CA cert: {}", e)))?;
    let ca_cert = X509::from_pem(&ca_cert_pem)
        .map_err(|e| ApiError::Internal(format!("Failed to parse CA cert: {}", e)))?;

    let ca_key_encrypted = fs::read("ca/ca.key")
        .map_err(|e| ApiError::Internal(format!("Failed to read CA key: {}", e)))?;

    let ca_password = std::env::var("CA_PASSWORD")
        .map_err(|_| ApiError::Internal("CA_PASSWORD env var not set".to_string()))?;

    let ca_private_key = PKey::private_key_from_pem_passphrase(&ca_key_encrypted, ca_password.as_bytes())
        .map_err(|e| ApiError::Internal(format!("Failed to decrypt CA key: {}", e)))?;

    // Subject (user's DN)
    let mut subject_name = X509Name::builder()
        .map_err(|e| ApiError::Internal(format!("X509Name::builder: {}", e)))?;

    subject_name.append_entry_by_text("CN", &pending_request.dn)
        .map_err(|e| ApiError::Internal(format!("append_entry_by_text: {}", e)))?;
    let subject_name = subject_name.build();
    builder.set_subject_name(&subject_name)
        .map_err(|e| ApiError::Internal(format!("set_subject_name: {}", e)))?;

    // Issuer (CA's subject)
    let issuer_name = ca_cert.subject_name();
    builder.set_issuer_name(issuer_name)
        .map_err(|e| ApiError::Internal(format!("set_issuer_name: {}", e)))?;

    // Serial number
    let mut serial_bn = BigNum::new().unwrap();
    serial_bn.pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    let serial = serial_bn.to_asn1_integer().unwrap();
    let serial_str = serial_bn.to_hex_str().unwrap().to_string();
    builder.set_serial_number(&serial).unwrap();

    // Set validity period
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|e| ApiError::Internal(format!("not_before: {}", e)))?;
    builder.set_not_before(&not_before)
        .map_err(|e| ApiError::Internal(format!("set_not_before: {}", e)))?;
    builder.set_not_after(&not_after)
        .map_err(|e| ApiError::Internal(format!("set_not_after: {}", e)))?;

    // Extensions (BasicConstraints: CA:FALSE, KeyUsage: digitalSignature/keyEncipherment)
    builder.append_extension(
        BasicConstraints::new().critical().build()
            .map_err(|e| ApiError::Internal(format!("BasicConstraints: {}", e)))?
    ).map_err(|e| ApiError::Internal(format!("append_extension: {}", e)))?;

    builder.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .map_err(|e| ApiError::Internal(format!("KeyUsage: {}", e)))?
    ).map_err(|e| ApiError::Internal(format!("append_extension: {}", e)))?;

    builder.append_extension(
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))
            .map_err(|e| ApiError::Internal(format!("SubjectKeyIdentifier: {}", e)))?
    ).map_err(|e| ApiError::Internal(format!("append_extension: {}", e)))?;

    builder.append_extension(
        AuthorityKeyIdentifier::new().keyid(true).build(&builder.x509v3_context(Some(&ca_cert), None))
            .map_err(|e| ApiError::Internal(format!("AuthorityKeyIdentifier: {}", e)))?
    ).map_err(|e| ApiError::Internal(format!("append_extension: {}", e)))?;

    // Sign with CA
    builder.sign(&ca_private_key, openssl::hash::MessageDigest::sha256())
        .map_err(|e| ApiError::Internal(format!("sign: {}", e)))?;

    let cert = builder.build();
    log::debug!("Built certificate with SN: {}", serial_str);

    Ok((cert, serial_str))
}

pub async fn generate_certificate(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<impl Responder, ApiError> {

    let user = match get_authorized_user_data(req, &state.pool).await {
        Ok(u) => u,
        Err(err) => {
            log::error!("Cannot get user data: {}", err);
            return Err(err);
        }
    };

    match generate_and_save_cert(path, user, &state.pool).await {
        Ok(ci) => Ok(HttpResponse::Ok().json(ci)),
        Err(err) => {
            log::error!("Cannot generate user certificate: {}", err);
            Err(err)
        }
    }
}

fn authorize_user(req: HttpRequest) -> Result<Uuid, ApiError> {
    // Authorization: Only admins may generate certificates
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    if claims.role != "ADMIN" && claims.role != "USER" {
        log::error!("User {} is not authorized generate certificate, but is not admin", claims.sub);
        return Err(ApiError::Unauthorized("Only admins and users can generate certificates".to_string()));
    }
    claims.sub.parse::<Uuid>().map_err(|_| ApiError::Unauthorized("Invalid UUID in claims".to_string()))
}

async fn get_authorized_user_data(req: HttpRequest, state_pool: &Pool<Postgres>) -> Result<User, ApiError> {
    let user_id = authorize_user(req)?;
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(state_pool)
        .map_err(|e| ApiError::Unauthorized(format!("Cannot authorize user {}", e)))
        .await
}

async fn generate_and_save_cert(path: web::Path<Uuid>, user: User, state_pool: &Pool<Postgres>) -> Result<CertificateInfo, ApiError> {
    // Find the pending certificate request by UUID
    let cert_req_id = path.into_inner();
    let pending_request = sqlx::query_as::<_, PendingCertificateInfo>(
        "SELECT id, validity_period_days as valid_days, dn
        FROM certificate_requests
        WHERE id = $1"
    )
        .bind(cert_req_id)
        .fetch_optional(state_pool)
        .await
        .map_err(|e| {
            log::error!("DB query error: {:?}", e);
            ApiError::Internal("DB error".into())
        })?;

    let pending_request = match pending_request {
        Some(req) => req,
        None => return Err(ApiError::NotFound("Pending certificate request not found".into())),
    };

    let validity_days = pending_request.valid_days.max(1) as u32; // minimum 1 day

    // Generate private key (RSA)
    let rsa = Rsa::generate(RSA_KEY_SIZE)
        .map_err(|e| ApiError::Internal(format!("Keygen error: {}", e)))?;
    let private_key = PKey::from_rsa(rsa)
        .map_err(|e| ApiError::Internal(format!("PKey error: {}", e)))?;
    let not_after = Asn1Time::days_from_now(validity_days)
        .map_err(|e| ApiError::Internal(format!("not_after: {}", e)))?;

    // Build certificate
    let (cert, serial_str) = build_certificate(&private_key, &pending_request, &not_after)?;

    // Encrypt the private key with user's password hash
    let key_pem = private_key.private_key_to_pem_pkcs8()
        .map_err(|e| ApiError::Internal(format!("private_key_to_pem_pkcs8: {}", e)))?;
    let cipher = Cipher::aes_256_cbc();
    let password_hash_bytes = user.password_hash.as_bytes();
    if password_hash_bytes.len() < 48 {
        return Err(ApiError::Internal("Password hash is too short for key derivation".to_string()));
    }
    let key = &password_hash_bytes[..32];
    let iv = &password_hash_bytes[32..48];
    let encrypted_key = openssl::symm::encrypt(cipher, key, Some(iv), &key_pem)
        .map_err(|e| ApiError::Internal(format!("Encrypt key: {}", e)))?;

    // Save certificate DER and encrypted private key to DB
    let cert_der = cert.to_der()
        .map_err(|e| ApiError::Internal(format!("cert.to_der: {}", e)))?;

    let expiration_date = Utc::now() + chrono::Duration::days(validity_days as i64);

    let cert_id: Uuid = sqlx::query_scalar(
        "INSERT INTO certificates (id, user_id, serial_number, status, expiration_date, certificate_der) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id")
        .bind(cert_req_id)
        .bind(user.id)
        .bind(&serial_str)
        .bind(CertificateStatus::ACTIVE)
        .bind(expiration_date)
        .bind(&cert_der)
        .fetch_one(state_pool)
        .await
        .map_err(|e| {
            log::error!("Failed to insert certificate into database: {}", e);
            e
        })?;

    sqlx::query(
        "INSERT INTO private_keys (id, certificate_id, encrypted_key, salt) VALUES ($1, $2, $3, $4)"
    )
        .bind(cert_id)
        .bind(cert_id)
        .bind(&encrypted_key)
        .bind(&[] as &[u8]) // Empty salt since we're using password hash directly
        .execute(state_pool)
        .await?;
    
    sqlx::query("UPDATE certificate_requests SET accepted_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(cert_req_id)
        .execute(state_pool)
        .await?;

    Ok(CertificateInfo {
        id: cert_id,
        serial_number: serial_str,
        dn: pending_request.dn,
        status: CertificateStatus::ACTIVE,
        expiration_date,
        renewed_count: 0,
        certificate_der: Vec::new(),
        renewal_date: Option::None,
    })
}

async fn get_user_certificate(cert_id: Uuid, user_id: Uuid, state_pool: &Pool<Postgres>) -> Result<CertificateInfo, ApiError> {
    sqlx::query_as::<_, CertificateInfo>(
        "SELECT c.id, c.serial_number, cr.dn, c.status, c.expiration_date, c.renewed_count, c.certificate_der, c.renewal_date 
        FROM certificates c 
        JOIN certificate_requests cr ON c.id=cr.id
        WHERE c.id = $1 AND c.user_id = $2"
    ).bind(cert_id)
        .bind(user_id)
        .fetch_optional(state_pool)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found or not owned by user".to_string()))
}

async fn generate_user_pkcs12(cert_id: Uuid,
                              user: User,
                              password: String,
                              state_pool: &Pool<Postgres>) -> Result<Vec<u8>, ApiError> {
    let certificate = match get_user_certificate(cert_id, user.id, state_pool).await {
        Ok(c) => c,
        Err(err) => { return Err(err); }
    };

    let enc_key_result = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT encrypted_key FROM private_keys WHERE certificate_id = $1"
        )
        .bind(certificate.id)
        .fetch_one(state_pool)
        .await;
    let encrypted_key = match enc_key_result {
        Ok(ek) => ek,
        Err(msg) => {
            log::error!("Error getting private key for {}: {}", certificate.id, msg);
            return Err(ApiError::NotFound("Private key not found".to_string()));
        }
    };

    // Decrypt the private key
    let cipher = Cipher::aes_256_cbc();
    let password_hash_bytes = user.password_hash.as_bytes();
    if password_hash_bytes.len() < 48 {
        return Err(ApiError::Internal("Password hash is too short for key derivation".to_string()));
    }
    let key = &password_hash_bytes[..32];
    let iv = &password_hash_bytes[32..48];
    let private_key_pem = decrypt(cipher, key, Some(iv), &encrypted_key)
        .map_err(|e| {
            log::error!("decrypt failed {}", e);
            ApiError::Internal(
                "Private key decryption failed. The key may be corrupt or the PIN hash changed."
                    .to_string(),
            )
        })?;

    // Create PKCS#12 archive
    let x509 = X509::from_der(&certificate.certificate_der)
        .map_err(|_| ApiError::Internal("Failed to parse certificate DER".to_string()))?;
    let pkey = PKey::private_key_from_pem(&private_key_pem)
        .map_err(|_| ApiError::Internal("Failed to parse private key PEM".to_string()))?;

    let pkcs12_builder = Pkcs12::builder()
        .cert(&x509)
        .pkey(&pkey)
        .build2(&password)
        .map_err(|e| ApiError::Internal(format!("Failed to build PKCS#12 archive: {}", e)))?;
    let pkcs12 = pkcs12_builder
        .to_der()
        .map_err(|e| ApiError::Internal(format!("Failed to serialize PKCS#12 archive: {}", e)))?;

    Ok(pkcs12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier};
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;

    #[test]
    fn test_key_generation() {
        let rsa = Rsa::generate(RSA_KEY_SIZE).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        assert_eq!(pkey.bits(), RSA_KEY_SIZE);
    }

    #[test]
    fn test_certificate_building_and_signing() {
        // Set CA_PASSWORD for test
        std::env::set_var("CA_PASSWORD", "ca_password");

        // Load CA certificate and private key
        let ca_cert_pem = fs::read("ca/ca.crt").unwrap();
        let ca_cert = X509::from_pem(&ca_cert_pem).unwrap();
        let ca_key_encrypted = fs::read("ca/ca.key").unwrap();
        let ca_private_key = PKey::private_key_from_pem_passphrase(&ca_key_encrypted, b"ca_password").unwrap();

        // Generate user private key
        let rsa = Rsa::generate(RSA_KEY_SIZE).unwrap();
        let private_key = PKey::from_rsa(rsa).unwrap();

        // Build certificate
        let mut builder = X509Builder::new().unwrap();
        builder.set_pubkey(&private_key).unwrap();

        // Set subject
        let mut subject_name = X509Name::builder().unwrap();
        subject_name.append_entry_by_text("CN", "test.example.com").unwrap();
        let subject_name = subject_name.build();
        builder.set_subject_name(&subject_name).unwrap();

        // Set issuer to CA
        let issuer_name = ca_cert.subject_name();
        builder.set_issuer_name(issuer_name).unwrap();

        // Set serial number
        let mut serial_bn_test = BigNum::new().unwrap();
        serial_bn_test.pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
        let serial = serial_bn_test.to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();

        // Set validity period
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        // Add extensions
        builder.append_extension(
            BasicConstraints::new().critical().build().unwrap()
        ).unwrap();
        builder.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build().unwrap()
        ).unwrap();
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None)).unwrap()
        ).unwrap();
        builder.append_extension(
            AuthorityKeyIdentifier::new().keyid(true).build(&builder.x509v3_context(Some(&ca_cert), None)).unwrap()
        ).unwrap();

        // Sign with CA
        builder.sign(&ca_private_key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        // Verify certificate properties
        let mut common_name_it = cert.subject_name().entries().filter(|e| e.object().nid() == Nid::COMMONNAME);
        let cn_ref = common_name_it.next()
            .unwrap()
            .data()
            .as_utf8()
            .expect("Expected CN String");
        assert_eq!(cn_ref.to_string(), "test.example.com");
        assert!(cert.verify(&ca_private_key).unwrap()); // Verify signature
    }
}
