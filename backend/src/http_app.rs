use crate::auth::{list_users, login, logout, register, verify_token};
use crate::certificate::{
    cancel_certificate_request, create_certificate_request, download_pkcs12,
    download_public_certificate, generate_certificate, list_all_certificates,
    list_expiring_certificates, list_pending_certificates, list_user_certificates,
    revoke_certificate,
};
use crate::db_model::AppState;
use crate::middleware::JwtMiddlewareFactory;
use actix_web::web::{self, ServiceConfig};

pub fn config_app(app_state: web::Data<AppState>) -> Box<dyn Fn(&mut ServiceConfig)> {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.app_data(app_state.clone())
            .route("/users", web::post().to(register)) // Public route for registration
            .route("/auth/login", web::post().to(login))
            .route("/auth/logout", web::post().to(logout))
            .route("/auth/verify", web::get().to(verify_token))
            // Protected routes
            .service(
                web::scope("")
                    .wrap(JwtMiddlewareFactory)
                    .route("/certificates/list", web::get().to(list_all_certificates))
                    .route(
                        "/users/{user_id}/certificates/list",
                        web::get().to(list_user_certificates),
                    )
                    .route(
                        "/users/{user_id}/certificates/pending",
                        web::get().to(list_pending_certificates),
                    )
                    .route(
                        "/users/{user_id}/certificates/request",
                        web::post().to(create_certificate_request),
                    )
                    .route(
                        "/users/{user_id}/certificates/request/{request_id}",
                        web::delete().to(cancel_certificate_request),
                    )
                    .route(
                        "/users/{user_id}/certificates/expiring",
                        web::get().to(list_expiring_certificates),
                    )
                    .route(
                        "/users/{user_id}/certificates/{cert_id}/generate",
                        web::post().to(generate_certificate),
                    )
                    .route(
                        "/users/{user_id}/certificates/{cert_id}/download",
                        web::get().to(download_public_certificate),
                    )
                    .route(
                        "/users/{user_id}/certificates/{cert_id}/pkcs12",
                        web::post().to(download_pkcs12),
                    )
                    .route(
                        "/users/{user_id}/certificates/{cert_id}/revoke",
                        web::put().to(revoke_certificate),
                    )
                    .route("/users", web::get().to(list_users)),
            );
    })
}
