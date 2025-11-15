use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::Claims,
    db_model::{CertificateInfo, CertificateStatus},
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

#[derive(serde::Serialize)]
pub struct ListCertificatesResponse {
    certificates: Vec<CertificateInfo>,
    total: i64,
    page: i64,
}

pub async fn list_certificates(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<ListCertificatesQuery>,
) -> Result<impl Responder, ApiError> {
    log::info!("Listing certificates");
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("Missing claims".to_string()))?;

    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiError::Internal("Invalid UUID in claims".into()))?;

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    let sort_by = query.sort_by.as_deref().unwrap_or("expiration_date");
    let order = query.order.as_deref().unwrap_or("asc");

    // Basic validation to prevent SQL injection
    let allowed_sort_columns = ["serial_number", "dn", "status", "expiration_date", "renewed_count"];
    if !allowed_sort_columns.contains(&sort_by) {
        return Err(ApiError::Internal("Invalid sort_by parameter".into()));
    }
    let order_direction = if order.eq_ignore_ascii_case("desc") { "DESC" } else { "ASC" };

    let status_filter = query.status.as_deref();

    // Build query for total count
    let count_query = "SELECT COUNT(*) FROM certificates WHERE user_id = $1".to_string()
        + if status_filter.is_some() { " AND status = $2" } else { "" };

    let mut count_query_builder = sqlx::query_scalar(&count_query).bind(user_id);
    if let Some(status) = status_filter {
        count_query_builder = count_query_builder.bind(status);
    }

    let total: i64 = count_query_builder.fetch_one(&state.pool).await?;

    // Build query for fetching certificates
    let select_query = format!(
        "SELECT id, serial_number, dn, status, expiration_date, renewed_count FROM certificates WHERE user_id = $1 {} ORDER BY {} {} LIMIT $2 OFFSET $3",
        if status_filter.is_some() { "AND status = $4" } else { "" },
        sort_by,
        order_direction
    );

    let mut query_builder = sqlx::query_as::<_, CertificateInfo>(&select_query)
        .bind(user_id)
        .bind(limit)
        .bind(offset);

    if let Some(status) = status_filter {
        let cert_status: CertificateStatus = match status.to_uppercase().as_str() {
            "ACTIVE" => CertificateStatus::ACTIVE,
            "EXPIRED" => CertificateStatus::EXPIRED,
            "REVOKED" => CertificateStatus::REVOKED,
            _ => return Err(ApiError::Internal("Invalid status filter".into())),
        };
        query_builder = query_builder.bind(cert_status);
    }

    let certificates = query_builder.fetch_all(&state.pool).await?;

    Ok(HttpResponse::Ok().json(ListCertificatesResponse {
        certificates,
        total,
        page,
    }))
}