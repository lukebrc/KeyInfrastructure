use actix_web::{web::{self, ServiceConfig}};
use crate::auth::{list_users, login, register, verify_token};
use crate::certificate::{create_certificate_request, download_certificate, generate_certificate, list_active_certificates, list_expiring_certificates, list_pending_certificates, revoke_certificate};
use crate::db_model::AppState;
use crate::middleware::JwtMiddlewareFactory;


pub fn config_app(app_state: web::Data<AppState>) -> Box<dyn Fn(&mut ServiceConfig)> {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.app_data(app_state.clone())
            .route("/users", web::post().to(register)) // Public route for registration
            .route("/auth/login", web::post().to(login))
            .route("/auth/verify", web::get().to(verify_token))
            // Protected routes
            .service(
                web::scope("")
                    .wrap(JwtMiddlewareFactory)
                    .route("/certificates", web::get().to(list_active_certificates))
                    .route("/certificates", web::post().to(create_certificate_request))
                    .route("/certificates/expiring", web::get().to(list_expiring_certificates))
                    .route("/certificates/pending", web::get().to(list_pending_certificates))
                    .route("/certificates/{cert_id}/generate", web::post().to(generate_certificate))
                    .route("/certificates/{cert_id}/download", web::post().to(download_certificate))
                    .route("/certificates/{cert_id}/revoke", web::put().to(revoke_certificate)),
            )
            .service(
                web::scope("/users")
                    .wrap(JwtMiddlewareFactory)
                    .route("/users", web::get().to(list_users))
            );
    })
}