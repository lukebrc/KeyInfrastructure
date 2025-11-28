use std::future::{ready, Ready};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
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

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let token = match req.headers().get("Authorization") {
            Some(header_value) => {
                if let Ok(value_str) = header_value.to_str() {
                    value_str.strip_prefix("Bearer ").map(String::from)
                } else {
                    // Header contains non-UTF8 characters, immediately reject.
                    return Box::pin(async { Err(ErrorUnauthorized("Invalid Authorization header encoding.")) });
                }
            }
            None => None,
        };

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
                    // Deconstruct, modify, and reconstruct the request to safely add extensions.
                    let (http_req, payload) = req.into_parts();
                    http_req.extensions_mut().insert(token_data.claims);
                    req = ServiceRequest::from_parts(http_req, payload);
                }
                Err(err) => {
                    log::warn!("Invalid token provided: {}", err);
                    return Box::pin(async { Err(ErrorUnauthorized("Invalid token")) });
                }
            }
            log::debug!("Validation OK for {} request: {}", req.method(), req.path());
        } else {
            log::warn!("No token was provided, but this is a protected route");
            return Box::pin(async { Err(ErrorUnauthorized("Authentication token required.")) });
        }

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            log::info!("Verifying token result: {}", res.status());
            Ok(res)
        })
    }
}
