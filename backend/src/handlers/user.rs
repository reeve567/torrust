use actix_web::{web, Responder, HttpResponse, HttpRequest};
use serde::{Deserialize, Serialize};
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Pbkdf2,
};
use std::borrow::Cow;
use crate::errors::{ServiceResult, ServiceError};
use crate::common::WebAppData;
use crate::models::response::OkResponse;
use crate::models::response::TokenResponse;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .service(web::resource("/register")
                .route(web::post().to(register)))
            .service(web::resource("/login")
                .route(web::post().to(login)))
            .service(web::resource("/ban/{user}")
                .route(web::delete().to(ban_user)))
    );
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Register {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Login {
    pub login: String,
    pub password: String,
}

pub async fn register(req: HttpRequest, payload: web::Json<Register>, app_data: WebAppData) -> ServiceResult<impl Responder> {
    let settings = app_data.cfg.settings.read().await;

    if payload.password != payload.confirm_password {
        return Err(ServiceError::PasswordsDontMatch);
    }

    let password_length = payload.password.len();
    if password_length <= settings.auth.min_password_length {
        return Err(ServiceError::PasswordTooShort);
    }
    if password_length >= settings.auth.max_password_length {
        return Err(ServiceError::PasswordTooLong);
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash;
    if let Ok(password) = Pbkdf2.hash_password(payload.password.as_bytes(), &salt) {
        password_hash = password.to_string();
    } else {
        return Err(ServiceError::InternalServerError);
    }

    if payload.username.contains('@') {
        return Err(ServiceError::UsernameInvalid)
    }

    let res = sqlx::query!(
        "INSERT INTO torrust_users (username, password) VALUES ($1, $2)",
        payload.username,
        password_hash,
    )
        .execute(&app_data.database.pool)
        .await;

    if let Err(sqlx::Error::Database(err)) = res {
        return if err.code() == Some(Cow::from("2067")) {
            if err.message().contains("torrust_users.username") {
                Err(ServiceError::UsernameTaken)
            } else {
                Err(ServiceError::InternalServerError)
            }
        } else {
            Err(sqlx::Error::Database(err).into())
        };
    }

    // count accounts
    let res_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM torrust_users")
        .fetch_one(&app_data.database.pool)
        .await?;

    // make admin if first account
    if res_count.0 == 1 {
        let _res_make_admin = sqlx::query!("UPDATE torrust_users SET administrator = 1")
            .execute(&app_data.database.pool)
            .await;
    }

    let conn_info = req.connection_info();

    Ok(HttpResponse::Ok())
}

pub async fn login(payload: web::Json<Login>, app_data: WebAppData) -> ServiceResult<impl Responder> {
    let settings = app_data.cfg.settings.read().await;

    let res = app_data.database.get_user_with_username(&payload.login).await;

    match res {
        Some(user) => {
            drop(settings);

            let parsed_hash = PasswordHash::new(&user.password)?;

            if !Pbkdf2.verify_password(payload.password.as_bytes(), &parsed_hash).is_ok() {
                return Err(ServiceError::WrongPasswordOrUsername);
            }

            let username = user.username.clone();
            let token = app_data.auth.sign_jwt(user.clone()).await;


            Ok(HttpResponse::Ok().json(OkResponse {
                data: TokenResponse {
                    token,
                    username,
                    admin: user.administrator
                }
            }))
        }
        None => Err(ServiceError::WrongPasswordOrUsername)
    }
}

pub async fn ban_user(req: HttpRequest, app_data: WebAppData) -> ServiceResult<impl Responder> {
    let user = app_data.auth.get_user_from_request(&req).await?;

    // check if user is administrator
    if !user.administrator { return Err(ServiceError::Unauthorized) }

    let to_be_banned_username = req.match_info().get("user").unwrap();

    let res = sqlx::query!(
        "DELETE FROM torrust_users WHERE username = ? AND administrator = 0",
        to_be_banned_username
    )
        .execute(&app_data.database.pool)
        .await;

    if let Err(_) = res { return Err(ServiceError::UsernameNotFound) }
    if res.unwrap().rows_affected() == 0 { return Err(ServiceError::UsernameNotFound) }

    Ok(HttpResponse::Ok().json(OkResponse {
        data: format!("Banned user: {}", to_be_banned_username)
    }))
}

pub async fn me(req: HttpRequest, app_data: WebAppData) -> ServiceResult<impl Responder> {
    let user = match app_data.auth.get_user_from_request(&req).await {
        Ok(user) => Ok(user),
        Err(e) => Err(e)
    }?;

    let username = user.username.clone();
    let token = app_data.auth.sign_jwt(user.clone()).await;

    Ok(HttpResponse::Ok().json(OkResponse {
        data: TokenResponse {
            token,
            username,
            admin: user.administrator
        }
    }))
}
