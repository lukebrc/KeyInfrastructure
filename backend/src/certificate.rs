use actix_web::{http::header, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::symm::{decrypt, Cipher};
use openssl::x509::{X509, X509Builder, X509Name};
use openssl::rsa::Rsa;
use openssl::asn1::Asn1Time;
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
    password: String,
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

    // Fetch the user to get their hashed password for encryption
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

    // Fetch certificate data and user password hash from DB
    let cert_row = sqlx::query_as::<_, CertificateDownloadInfo>(
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
    if cert_row.user_id != user_id {
        log::error!(
            "User {} is not allowed to download certificate {}",
            user_id,
            cert_id
        );
        return Err(ApiError::Forbidden(
            "You are not allowed to download this certificate".to_string(),
        ));
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    // Verify password against the user's stored hash
    if !bcrypt::verify(&body.password, &user.password_hash)
        .map_err(|_| ApiError::Internal("password verification failed".to_string()))?
    {
        return Err(ApiError::BadRequest("Incorrect PIN".to_string()));
    }

    // Decrypt the private key
    let cipher = Cipher::aes_256_cbc();
    let key = &user.password_hash.as_bytes()[..32];
    let iv = &user.password_hash.as_bytes()[32..48];
    let encrypted_private_key = general_purpose::STANDARD
        .decode(&cert_row.encrypted_private_key)
        .map_err(|_| ApiError::Internal("Failed to decode private key".to_string()))?;
    let private_key_pem = decrypt(cipher, key, Some(iv), &encrypted_private_key).map_err(|_| {
        ApiError::Internal(
            "Private key decryption failed. The key may be corrupt or the PIN hash changed."
                .to_string(),
        )
    })?;

    // Create PKCS#12 archive
    let x509 = X509::from_der(cert_row.certificate_der.as_bytes())
        .map_err(|_| ApiError::Internal("Failed to parse certificate PEM".to_string()))?;
    let pkey = PKey::private_key_from_pem(&private_key_pem)
        .map_err(|_| ApiError::Internal("Failed to parse private key PEM".to_string()))?;

    let pkcs12_builder = Pkcs12::builder()
        .cert(&x509)
        .pkey(&pkey)
        .build2(&body.password)
        .map_err(|e| ApiError::Internal(format!("Failed to build PKCS#12 archive: {}", e)))?;
    let pkcs12 = pkcs12_builder
        .to_der()
        .map_err(|e| ApiError::Internal(format!("Failed to serialize PKCS#12 archive: {}", e)))?;

    let filename = format!("attachment; filename=\"{}.p12\"", &cert_row.dn);
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
    use openssl::bn::BigNum;
    let mut serial_bn = BigNum::new().unwrap();
    serial_bn.pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    let serial = serial_bn.to_asn1_integer().unwrap();
    let serial_str = serial_bn.to_hex_str().unwrap().to_string();
    builder.set_serial_number(&serial).unwrap();

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
        AuthorityKeyIdentifier::new().keyid(true).build(&builder.x509v3_context(Some(&ca_cert), None))
            .map_err(|e| ApiError::Internal(format!("AuthorityKeyIdentifier: {}", e)))?
    ).map_err(|e| ApiError::Internal(format!("append_extension: {}", e)))?;

    // Sign with CA
    builder.sign(&ca_private_key, openssl::hash::MessageDigest::sha256())
        .map_err(|e| ApiError::Internal(format!("sign: {}", e)))?;

    let cert = builder.build();

    // Get user for password hash
    let user_id = claims.sub.parse::<Uuid>()
        .map_err(|_| ApiError::Internal("Invalid user ID in claims".to_string()))?;
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| ApiError::NotFound("User not found".to_string()))?;

    // Encrypt the private key with user's password hash
    let key_pem = private_key.private_key_to_pem_pkcs8()
        .map_err(|e| ApiError::Internal(format!("private_key_to_pem_pkcs8: {}", e)))?;
    let cipher = Cipher::aes_256_cbc();
    let key = &user.password_hash.as_bytes()[..32];
    let iv = &user.password_hash.as_bytes()[32..48];
    let encrypted_key = openssl::symm::encrypt(cipher, key, Some(iv), &key_pem)
        .map_err(|e| ApiError::Internal(format!("Encrypt key: {}", e)))?;
    let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);

    // Save certificate DER and encrypted private key to DB
    let _cert_der = cert.to_der()
        .map_err(|e| ApiError::Internal(format!("cert.to_der: {}", e)))?;
    let expiration_date = not_after.to_string();

    let cert_id: Uuid = sqlx::query_scalar(
        "INSERT INTO certificates (id, user_id, serial_number, dn, status, expiration_date, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id"
    )
    .bind(cert_req_id)
    .bind(user_id)
    .bind(&serial_str)
    .bind(&pending_request.dn)
    .bind("ACTIVE")
    .bind(expiration_date.to_string())
    .fetch_one(&state.pool)
    .await?;

    sqlx::query(
        "INSERT INTO private_keys (id, encrypted_key) VALUES ($1, $2)"
    )
    .bind(cert_id)
    .bind(encrypted_key_b64)
    .execute(&state.pool)
    .await?;

    // Delete the pending request
    sqlx::query("DELETE FROM certificate_requests WHERE id = $1")
        .bind(cert_req_id)
        .execute(&state.pool)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": cert_id,
        "serial_number": serial_str,
        "dn": pending_request.dn,
        "status": "ACTIVE",
        "expiration_date": expiration_date
    })))
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
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        assert_eq!(pkey.bits(), 2048);
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
        let rsa = Rsa::generate(2048).unwrap();
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
