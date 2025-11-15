use std::future::{ready, Ready};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use actix_web::error::ErrorInternalServerError;
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::auth::Claims;

pub struct JwtMiddlewareFactory;

impl<S, B> Transform<S, ServiceRequest> for JwtMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddleware { service }))
    }
}

pub struct JwtMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for JwtMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let token = match req.headers().get("Authorization") {
            Some(value) => {
                let parts: Vec<&str> = value.to_str().unwrap_or("").split_whitespace().collect();
                if parts.len() == 2 && parts[0] == "Bearer" {
                    Some(parts[1].to_string())
                } else {
                    log::warn!("Invalid authorization header: {:?}", value);
                    None
                }
            }
            None => None,
        };
        log::info!("Verifying token: {}", token.is_some());
        log::debug!("Verifying token: {:?}", token);

        if let Some(token) = token {
            let state = match req.app_data::<actix_web::web::Data<crate::AppState>>() {
                Some(state) => state,
                None => {
                    log::error!("App state not configured");
                    return Box::pin(async { Err(ErrorInternalServerError("App state not configured")) })
                }
            };

            let decoding_key = DecodingKey::from_secret(state.jwt_secret.as_ref());
            let validation = Validation::default();

            match decode::<Claims>(&token, &decoding_key, &validation) {
                Ok(token_data) => {
                    req.extensions_mut().insert(token_data.claims);
                }
                Err(err) => {
                    log::error!("Token is invalid: {:?}", err);
                    // Token is invalid, but we don't error out here.
                    // The handler will decide if it needs a valid token.
                }
            }
            log::info!("Validation {:?}", validation);
        }

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            log::info!("Verifying token result: {}", res.status());
            Ok(res)
        })
    }
}
