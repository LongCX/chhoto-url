// SPDX-FileCopyrightText: 2023 Sayantan Santra <sayantan.santra689@gmail.com>
// SPDX-License-Identifier: MIT

use actix_files::NamedFile;
use actix_session::Session;
use actix_web::{
    delete, get,
    http::StatusCode,
    post, put,
    web::{self, Redirect},
    Either, HttpRequest, HttpResponse, Responder,
};
use log::{info};
use serde::{Deserialize, Serialize};
use std::env;
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier};
use crate::AppState;
use crate::{auth, database};
use crate::{auth::is_session_valid, utils};
use crate::openid::{exchange_code, generate_auth_url, initialize_openid, CallbackRequest};
use ChhotoError::{ClientError, ServerError};

// Store the version number
const VERSION: &str = env!("CARGO_PKG_VERSION");

const SESSION_KEY_OIDC_STATE: &str = "oidc_state";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserSessionData {
    pub user_id: String,
    pub email: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Serialize)]
struct AuthUrlResponse {
    auth_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OidcState {
    pub state: CsrfToken,
    pub nonce: Nonce,
    pub pkce_verifier: PkceCodeVerifier,
}

// Error types
pub enum ChhotoError {
    ServerError,
    ClientError { reason: String },
}

// Define JSON struct for returning success/error data
#[derive(Serialize)]
pub struct JSONResponse {
    pub success: bool,
    pub error: bool,
    pub reason: String,
}

// Define JSON struct for returning backend config
#[derive(Serialize)]
struct BackendConfig {
    version: String,
    site_url: Option<String>,
    allow_capital_letters: bool,
    public_mode: bool,
    public_mode_expiry_delay: i64,
    slug_style: String,
    slug_length: usize,
    try_longer_slug: bool,
}

// Needed to return the short URL to make it easier for programs leveraging the API
#[derive(Serialize)]
struct CreatedURL {
    success: bool,
    error: bool,
    shorturl: String,
    expiry_time: i64,
}

// Struct for returning information about a shortlink in expand
#[derive(Serialize)]
struct LinkInfo {
    success: bool,
    error: bool,
    longurl: String,
    hits: i64,
    expiry_time: i64,
}

// Struct for query params in /api/all
#[derive(Deserialize)]
pub struct GetReqParams {
    pub page_after: Option<String>,
    pub page_no: Option<i64>,
    pub page_size: Option<i64>,
}

// Define the routes

// Add new links
#[post("/api/new")]
pub async fn add_link(
    req: String,
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    // Call is_api_ok() function, pass HttpRequest
    let result = auth::is_api_ok(http, config);
    // If success, add new link
    if result.success {
        match utils::add_link(&req, &data.db, config, false) {
            Ok((shorturl, expiry_time)) => {
                let site_url = config.site_url.clone();
                let shorturl = if let Some(url) = site_url {
                    format!("{url}/{shorturl}")
                } else {
                    let protocol = if config.port == 443 { "https" } else { "http" };
                    let port_text = if [80, 443].contains(&config.port) {
                        String::new()
                    } else {
                        format!(":{}", config.port)
                    };
                    format!("{protocol}://localhost{port_text}/{shorturl}")
                };
                let response = CreatedURL {
                    success: true,
                    error: false,
                    shorturl,
                    expiry_time,
                };
                HttpResponse::Created().json(response)
            }
            Err(ServerError) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when adding the link.".to_string(),
                };
                HttpResponse::InternalServerError().json(response)
            }
            Err(ClientError { reason }) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::Conflict().json(response)
            }
        }
    } else if result.error {
        HttpResponse::Unauthorized().json(result)
    // If password authentication or public mode is used - keeps backwards compatibility
    } else {
        let result = if auth::is_session_valid(session) {
            utils::add_link(&req, &data.db, config, false)
        } else if config.public_mode {
            utils::add_link(&req, &data.db, config, true)
        } else {
            return HttpResponse::Unauthorized().body("Not logged in!");
        };
        match result {
            Ok((shorturl, _)) => HttpResponse::Created().body(shorturl),
            Err(ServerError) => HttpResponse::InternalServerError()
                .body("Something went wrong when adding the link.".to_string()),
            Err(ClientError { reason }) => HttpResponse::Conflict().body(reason),
        }
    }
}

// Return all active links
#[get("/api/all")]
pub async fn getall(
    data: web::Data<AppState>,
    session: Session,
    params: web::Query<GetReqParams>,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    // Call is_api_ok() function, pass HttpRequest
    let result = auth::is_api_ok(http, config);
    // If success, return all links
    if result.success {
        HttpResponse::Ok().body(utils::getall(&data.db, params.into_inner()))
    } else if result.error {
        HttpResponse::Unauthorized().json(result)
    // If password authentication is used - keeps backwards compatibility
    } else if auth::is_session_valid(session) {
        HttpResponse::Ok().body(utils::getall(&data.db, params.into_inner()))
    } else {
        HttpResponse::Unauthorized().body("Not logged in!")
    }
}

// Get information about a single shortlink
#[post("/api/expand")]
pub async fn expand(req: String, data: web::Data<AppState>, http: HttpRequest) -> HttpResponse {
    let result = auth::is_api_ok(http, &data.config);
    if result.success {
        match database::find_url(&req, &data.db) {
            Ok((longurl, hits, expiry_time)) => {
                let body = LinkInfo {
                    success: true,
                    error: false,
                    longurl,
                    hits,
                    expiry_time,
                };
                HttpResponse::Ok().json(body)
            }
            Err(ServerError) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when finding the link.".to_string(),
                };
                HttpResponse::BadRequest().json(body)
            }
            Err(ClientError { reason }) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::BadRequest().json(body)
            }
        }
    } else {
        HttpResponse::Unauthorized().json(result)
    }
}

// Get information about a single shortlink
#[put("/api/edit")]
pub async fn edit_link(
    req: String,
    session: Session,
    data: web::Data<AppState>,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config);
    if result.success || is_session_valid(session) {
        match utils::edit_link(&req, &data.db, config) {
            Ok(()) => {
                let body = JSONResponse {
                    success: true,
                    error: false,
                    reason: String::from("Edit was successful."),
                };
                HttpResponse::Created().json(body)
            }
            Err(ServerError) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when editing the link.".to_string(),
                };
                HttpResponse::InternalServerError().json(body)
            }
            Err(ClientError { reason }) => {
                let body = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::BadRequest().json(body)
            }
        }
    } else {
        HttpResponse::Unauthorized().json(result)
    }
}

// Get the site URL
// This is deprecated, and might be removed in the future.
// Use /api/getconfig instead
#[get("/api/siteurl")]
pub async fn siteurl(data: web::Data<AppState>) -> HttpResponse {
    if let Some(url) = &data.config.site_url {
        HttpResponse::Ok().body(url.clone())
    } else {
        HttpResponse::Ok().body("unset")
    }
}

// Get the version number
// This is deprecated, and might be removed in the future.
// Use /api/getconfig instead
#[get("/api/version")]
pub async fn version() -> HttpResponse {
    HttpResponse::Ok().body(format!("Chhoto URL v{VERSION}"))
}

// Get the user's current role
#[get("/api/whoami")]
pub async fn whoami(
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config);
    let acting_user = if result.success || is_session_valid(session) {
        "admin"
    } else if config.public_mode {
        "public"
    } else {
        "nobody"
    };
    HttpResponse::Ok().body(acting_user)
}

// Get some useful backend config
#[get("/api/getconfig")]
pub async fn getconfig(
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    let result = auth::is_api_ok(http, config);
    if result.success || is_session_valid(session) || data.config.public_mode {
        let backend_config = BackendConfig {
            version: VERSION.to_string(),
            allow_capital_letters: config.allow_capital_letters,
            public_mode: config.public_mode,
            public_mode_expiry_delay: config.public_mode_expiry_delay,
            site_url: config.site_url.clone(),
            slug_style: config.slug_style.clone(),
            slug_length: config.slug_length,
            try_longer_slug: config.try_longer_slug,
        };
        HttpResponse::Ok().json(backend_config)
    } else {
        HttpResponse::Unauthorized().json(result)
    }
}

// 404 error page
pub async fn error404() -> impl Responder {
    NamedFile::open_async("./resources/static/404.html")
        .await
        .customize()
        .with_status(StatusCode::NOT_FOUND)
}

// Handle a given shortlink
#[get("/{shortlink}")]
pub async fn link_handler(
    shortlink: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    let shortlink_str = shortlink.as_str();
    if let Ok(longlink) = database::find_and_add_hit(shortlink_str, &data.db) {
        if data.config.use_temp_redirect {
            Either::Left(Redirect::to(longlink))
        } else {
            // Defaults to permanent redirection
            Either::Left(Redirect::to(longlink).permanent())
        }
    } else {
        Either::Right(
            NamedFile::open_async("./resources/static/404.html")
                .await
                .customize()
                .with_status(StatusCode::NOT_FOUND),
        )
    }
}

#[get("/api/openid/login")]
async fn get_openid_login_url(
    data: web::Data<AppState>,
    session: Session,
) -> impl Responder {
    let config = &data.config;
    let openid_client = initialize_openid(config)
        .await
        .expect("Failed to initialize OpenID Connect client");
    match generate_auth_url(&openid_client) {
        (auth_url, csrf_token, nonce, verifier) => {
            // Lưu verifier và nonce vào session tạm thời (OPENID_TEMP)
            session
                .insert(
                    SESSION_KEY_OIDC_STATE,
                    OidcState {
                        state: csrf_token,
                        nonce,
                        pkce_verifier: verifier,
                    },
                ).expect("Failed to insert session oidc");
            HttpResponse::Ok().json(AuthUrlResponse {
                auth_url,
            })
        }
    }
}

#[post("/api/openid/callback")]
async fn openid_callback(
    data: web::Data<AppState>,
    session: Session,
    body: web::Json<CallbackRequest>,
    http: HttpRequest,
) -> impl Responder {
    let config = &data.config;
    let openid_client = initialize_openid(config)
        .await
        .expect("Failed to initialize OpenID Connect client");

    let oidc_state = session
        .remove_as::<OidcState>(SESSION_KEY_OIDC_STATE).unwrap().unwrap();

    match exchange_code(
        config,
        &openid_client,
        body.code.clone(),
        body.iss.clone(),
        body.state.clone(),
        oidc_state,
    )
        .await
    {
        Ok((user_id, email)) => {
            let user_agent = http
                .headers()
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("Unknown");
            let session_data = UserSessionData {
                user_id: user_id.to_string(),
                email: Some(email.to_string()),
                user_agent: Some(user_agent.to_string()),
            };
            let user_data = serde_json::to_string(&session_data)
                .expect("Failed to serialize session data");
            session.insert("chhoto-url", user_data)
                .expect("Failed to insert session data");

            HttpResponse::Ok().json(JSONResponse {
                success: true,
                error: false,
                reason: String::from("Authenticated successfully."),
            })
        }
        Err(_) => {
            HttpResponse::Unauthorized().json(JSONResponse {
                success: false,
                error: true,
                reason: String::from("Authentication failed."),
            })
        },
    }
}

// Handle logout
// There's no reason to be calling this route with an API key
#[delete("/api/logout")]
pub async fn logout(session: Session) -> HttpResponse {
    session.purge();
    info!("Successful logout.");
    HttpResponse::Ok().body("Logged out!")
}

// Delete a given shortlink
#[delete("/api/del/{shortlink}")]
pub async fn delete_link(
    shortlink: web::Path<String>,
    data: web::Data<AppState>,
    session: Session,
    http: HttpRequest,
) -> HttpResponse {
    let config = &data.config;
    // Call is_api_ok() function, pass HttpRequest
    let result = auth::is_api_ok(http, config);
    // If success, delete shortlink
    if result.success {
        match utils::delete_link(&shortlink, &data.db, data.config.allow_capital_letters) {
            Ok(()) => {
                let response = JSONResponse {
                    success: true,
                    error: false,
                    reason: format!("Deleted {shortlink}"),
                };
                HttpResponse::Ok().json(response)
            }
            Err(ServerError) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason: "Something went wrong when deleting the link.".to_string(),
                };
                HttpResponse::InternalServerError().json(response)
            }
            Err(ClientError { reason }) => {
                let response = JSONResponse {
                    success: false,
                    error: true,
                    reason,
                };
                HttpResponse::NotFound().json(response)
            }
        }
    } else if result.error {
        HttpResponse::Unauthorized().json(result)
    // If using password - keeps backwards compatibility
    } else if auth::is_session_valid(session) {
        if utils::delete_link(&shortlink, &data.db, data.config.allow_capital_letters).is_ok() {
            HttpResponse::Ok().body(format!("Deleted {shortlink}"))
        } else {
            HttpResponse::NotFound().body("Not found!")
        }
    } else {
        HttpResponse::Unauthorized().body("Not logged in!")
    }
}
