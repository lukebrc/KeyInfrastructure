use actix_web::{http::header, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::symm::{decrypt, Cipher};
use openssl::x509::{X509, X509Builder, X509Name};
use openssl::rsa::Rsa;
use openssl::asn1::Asn1Time;
use openssl::sign::Signer;
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

use crate::{
    auth::Claims,
    db_model::{CertificateInfo, CertificateStatus, User},
    errors::ApiError,
    AppState,
};

#[derive(Deserialize, Debug)]
pub struct ListCertificatesQuery {
    page: Option<i64>,
    limit: Option<i64>,
    status: Option<String>,
    sort_by: Option<String>,
    order: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateCertificateRequest {
    user_id: Uuid,
    dn: String,
    days_valid: i64,
}

#[derive(Deserialize)]
pub struct DownloadCertificateRequest {
    pin: String,
}

#[derive(Serialize)]
pub struct ListCertificatesResponse {
    certificates: Vec<CertificateInfo>,
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

#[derive(sqlx::FromRow)]
struct CertificateDownloadInfo {
    user_id: Uuid,
    dn: String,
    certificate_der: String,
    encrypted_private_key: String,
    pin_hash: String,
}

pub async fn create_certificate_request(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateCertificateRequest>,
) -> Result<impl Responder, ApiError> {
    log::info!(
        "Attempting to create certificate for user_id: {}",
        body.user_id
    );
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    // Authorization: Only admins can create certificates.
    if claims.role != "ADMIN" {
        log::error!("user_id: {} is not Admin", body.user_id);
        return Err(ApiError::Forbidden(
            "Only admins can create certificates".to_string(),
        ));
    }

    // Fetch the user to get their hashed PIN for encryption
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(body.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    let days_valid = body.days_valid;
    log::info!(
        "Adding certificate request for user {} dn: {}, days_valid: {}",
        body.user_id,
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

pub async fn download_certificate(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<DownloadCertificateRequest>,
) -> Result<impl Responder, ApiError> {
    let cert_id = path.into_inner();
    log::info!("Attempting to download certificate with id: {}", cert_id);
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    // Fetch certificate data and user PIN hash from DB
    let row = sqlx::query_as::<_, CertificateDownloadInfo>(
        "SELECT c.user_id, cr.dn, c.certificate_der, pk.encrypted_key
        FROM certificates c
        JOIN certificate_requests cr ON cr.id=c.id
        JOIN users u ON c.user_id = u.id
        JOIN private_keys pk on pk.id=c.id
        WHERE c.id = $1",
    )
    .bind(cert_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("Certificate not found".to_string()))?;

    // Authorization: User can only download their own certificate.
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::Internal("Invalid UUID in claims".to_string()))?;
    if row.user_id != user_id {
        log::error!(
            "User {} is not allowed to download certificate {}",
            user_id,
            cert_id
        );
        return Err(ApiError::Forbidden(
            "You are not allowed to download this certificate".to_string(),
        ));
    }
    // Verify PIN against the user's stored hash
    if !bcrypt::verify(&body.pin, &row.pin_hash)
        .map_err(|_| ApiError::Internal("PIN verification failed".to_string()))?
    {
        return Err(ApiError::BadRequest("Incorrect PIN".to_string()));
    }

    // Decrypt the private key
    let cipher = Cipher::aes_256_cbc();
    let key = &row.pin_hash.as_bytes()[..32];
    let iv = &row.pin_hash.as_bytes()[32..48];
    let encrypted_private_key = general_purpose::STANDARD
        .decode(&row.encrypted_private_key)
        .map_err(|_| ApiError::Internal("Failed to decode private key".to_string()))?;
    let private_key_pem = decrypt(cipher, key, Some(iv), &encrypted_private_key).map_err(|_| {
        ApiError::Internal(
            "Private key decryption failed. The key may be corrupt or the PIN hash changed."
                .to_string(),
        )
    })?;

    // Create PKCS#12 archive
    let x509 = X509::from_der(row.certificate_der.as_bytes())
        .map_err(|_| ApiError::Internal("Failed to parse certificate PEM".to_string()))?;
    let pkey = PKey::private_key_from_pem(&private_key_pem)
        .map_err(|_| ApiError::Internal("Failed to parse private key PEM".to_string()))?;

    let pkcs12_builder = Pkcs12::builder()
        .cert(&x509)
        .pkey(&pkey)
        .build2(&body.pin)
        .map_err(|e| ApiError::Internal(format!("Failed to build PKCS#12 archive: {}", e)))?;
    let pkcs12 = pkcs12_builder
        .to_der()
        .map_err(|e| ApiError::Internal(format!("Failed to serialize PKCS#12 archive: {}", e)))?;

    let filename = format!("attachment; filename=\"{}.p12\"", &row.dn);
    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_DISPOSITION, filename))
        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
        .body(pkcs12))
}

pub async fn list_active_certificates(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<ListCertificatesQuery>,
) -> Result<impl Responder, ApiError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::Internal("Invalid UUID in claims".into()))?;

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    let sort_by = query.sort_by.as_deref().unwrap_or("expiration_date");
    let order = query.order.as_deref().unwrap_or("asc");
    log::info!(
        "Listing certificates for user {}, page {}, offset {}",
        user_id,
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

    let mut count_query_builder = sqlx::query_scalar(&count_query).bind(user_id);
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
        "SELECT id, serial_number, dn, status, expiration_date, renewed_count FROM certificates WHERE user_id = $1 {} ORDER BY {} {} {}",
        status_clause,
        sort_by,
        order_direction,
        limit_offset_params
    );

    let mut query_builder = sqlx::query_as::<_, CertificateInfo>(&select_query).bind(user_id);

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

pub async fn list_pending_certificates(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::Internal("Invalid UUID in claims".into()))?;
    log::info!("Listing pending certificates for user {}", user_id);

    let rows = sqlx::query_as::<_, PendingCertificateInfo>(
        "SELECT cr.id, cr.validity_period_days as valid_days, cr.dn
            FROM certificate_requests cr
            WHERE cr.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(certificates) => {
            Ok(HttpResponse::Ok().json(ListPendingCertificatesResponse { certificates }))
        }
        Err(err) => {
            log::error!("Could not get certificates {}", err);
            Ok(HttpResponse::InternalServerError().body(err.to_string()))
        }
    }
}

pub async fn generate_certificate(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<impl Responder, ApiError> {
    use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier};
    use openssl::nid::Nid;

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

    // Find the pending certificate request by UUID
    let cert_req_id = path.into_inner();
    let pending_request = sqlx::query_as::<_, PendingCertificateInfo>(
        "SELECT id, validity_period_days as valid_days, dn
        FROM certificate_requests
        WHERE id = $1"
    )
    .bind(cert_req_id)
    .fetch_optional(&state.pool)
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

    // Generate private key (RSA 2048)
    let rsa = Rsa::generate(2048)
        .map_err(|e| ApiError::Internal(format!("Keygen error: {}", e)))?;
    let private_key = PKey::from_rsa(rsa)
        .map_err(|e| ApiError::Internal(format!("PKey error: {}", e)))?;

    // Build certificate
    let mut builder = X509Builder::new()
        .map_err(|e| ApiError::Internal(format!("X509Builder error: {}", e)))?;

    builder.set_pubkey(&private_key)
        .map_err(|e| ApiError::Internal(format!("set_pubkey: {}", e)))?;

    // Subject and issuer (for now, just set as DN from the request)
    let mut subject_name = X509Name::builder()
        .map_err(|e| ApiError::Internal(format!("X509Name::builder: {}", e)))?;

    subject_name.append_entry_by_text("CN", &pending_request.dn)
        .map_err(|e| ApiError::Internal(format!("append_entry_by_text: {}", e)))?;
    let subject_name = subject_name.build();
    builder.set_subject_name(&subject_name)
        .map_err(|e| ApiError::Internal(format!("set_subject_name: {}", e)))?;
    builder.set_issuer_name(&subject_name)
        .map_err(|e| ApiError::Internal(format!("set_issuer_name: {}", e)))?;

    // Serial number
    use openssl::bn::BigNum;
    let serial = BigNum::new()
        .and_then(|mut bn| { bn.pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?; bn.to_asn1_integer() })
        .map_err(|e| ApiError::Internal(format!("Serial: {}", e)))?;
    builder.set_serial_number(&serial)
        .map_err(|e| ApiError::Internal(format!("set_serial_number: {}", e)))?;

    // Set validity period
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|e| ApiError::Internal(format!("not_before: {}", e)))?;
    let not_after = Asn1Time::days_from_now(validity_days)
        .map_err(|e| ApiError::Internal(format!("not_after: {}", e)))?;
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
        AuthorityKeyIdentifier::new().keyid(true).build(&builder.x509v3_context(None, None))
            .map_err(|e| ApiError::Internal(format!("AuthorityKeyIdentifier: {}", e)))?
    ).map_err(|e| ApiError::Internal(format!("append_extension: {}", e)))?;

    // Sign (self-signed for now)
    builder.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .map_err(|e| ApiError::Internal(format!("sign: {}", e)))?;

    let cert = builder.build();

    // Save certificate and private key as PEM for download (or later, as DER for DB)
    let cert_pem = cert.to_pem()
        .map_err(|e| ApiError::Internal(format!("cert.to_pem: {}", e)))?;
    let key_pem = private_key.private_key_to_pem_pkcs8()
        .map_err(|e| ApiError::Internal(format!("private_key_to_pem_pkcs8: {}", e)))?;

    // For now, just return them concatenated as plain text
    let mut output = Vec::new();
    output.extend_from_slice(&cert_pem);
    output.extend_from_slice(b"\n");
    output.extend_from_slice(&key_pem);

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", "application/x-pem-file"))
        .body(output))
}
