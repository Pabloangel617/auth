use actix_web::{HttpServer, App, post, Responder, web, Result};
use serde::{Deserialize, Serialize};
use itsdangerous::{default_builder, IntoTimestampSigner, TimestampSigner};
use base64_url::{encode, decode};


#[derive(Debug, Deserialize, Serialize)]
struct HashPw {
    password: String
}

#[derive(Debug, Deserialize)]
struct Tokenize {
    user_id: String,
    password: String
}

#[derive(Debug, Deserialize)]
struct ValidateToken {
    user_id: String,
    password: String,
    token: String
}

#[derive(Debug, Serialize)]
struct ValidateResponse {
    is_valid: bool
}

fn make_token(user_id: String, password: String) -> String {
    let signer = default_builder(password).build().into_timestamp_signer();

    signer.sign(encode(&user_id))
}

fn verify_token(user_id: String, token: String, password: String) -> bool {
    let signer = default_builder(password).build().into_timestamp_signer();

    match signer.unsign(&token) {
        Ok(unsigned_value) => {
            let value = unsigned_value.value().to_string();

            match decode(&value) {
                Ok(v) => {
                    match std::str::from_utf8(&v) {
                        Ok(uid) => {
                            user_id == uid
                        },
                        Err(_) => false,
                    }
                },
                Err(_) => false
            }
        },
        Err(_) => false
    }
}


#[post("/token")]
async fn post_token(tokenize: web::Json<Tokenize>) -> Result<impl Responder> {
    let token = make_token(tokenize.user_id.to_string(), tokenize.password.to_string());

    let obj = HashPw {
        password: token
    };

    Ok(web::Json(obj))
}


#[post("/validate")]
async fn validate_token(maybevalid: web::Json<ValidateToken>) -> Result<impl Responder> {
    let is_valid = verify_token(maybevalid.user_id.to_string(), maybevalid.token.to_string(), maybevalid.password.to_string());

    let obj = ValidateResponse {
        is_valid
    };

    Ok(web::Json(obj))
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .service(post_token)
        .service(validate_token)
    })
    .bind(("0.0.0.0", 4600))?
    .run()
    .await
}
