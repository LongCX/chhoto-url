use crate::config::Config;
use openidconnect::{core::{CoreClient, CoreProviderMetadata, CoreResponseType}, reqwest::async_http_client, AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CallbackRequest {
    pub code: String,
}

pub async fn initialize_openid(
    config: &Config,
) -> Result<CoreClient, Box<dyn std::error::Error>> {
    let issuer_url = IssuerUrl::new(config.oidc_issuer_url.clone().unwrap_or_default())?;

    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oidc_client_id.clone().unwrap_or_default()),
        None, // No client_secret for public client
    )
        .set_redirect_uri(RedirectUrl::new(config.oidc_redirect_uri.clone().unwrap_or_default())?);

    Ok(client)
}

pub fn generate_auth_url(
    client: &CoreClient,
) -> (String, String, String, String) {
    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // authorize_url() trả về AuthorizationRequest
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge)
        .url();

    (
        auth_url.to_string(),
        pkce_verifier.secret().to_string(),
        nonce.secret().to_string(),
        csrf_token.secret().to_string(),
    )
}

pub async fn exchange_code(
    client: &CoreClient,
    code: String,
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
) -> Result<String, Box<dyn std::error::Error>> {
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    // Lấy ID token
    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or("No ID token in response")?;

    // Verify ID token và extract claims
    let token_claims = id_token
        .claims(
            &client.id_token_verifier(),
            &nonce,
        )
        .map_err(|e| format!("Failed to verify ID token: {}", e))?;

    // 1. Verify nonce từ ID token claims
    if let Some(token_nonce) = token_claims.nonce() {
        if token_nonce.secret() != nonce.secret() {
            return Err("Nonce mismatch - potential replay attack!".into());
        }
    } else {
        return Err("No nonce in ID token claims".into());
    }

    // 2. Verify issuer (tùy chọn - thư viện thường tự động verify)
    let issuer = token_claims.issuer();
    println!("Token issuer: {:?}", issuer);

    // 3. Verify audience (client_id)
    let audience = token_claims.audiences();
    println!("Token audience: {:?}", audience);

    // Trích xuất subject (user ID từ OpenID Provider)
    let user_id = token_claims.subject().to_string();

    Ok(user_id)
}