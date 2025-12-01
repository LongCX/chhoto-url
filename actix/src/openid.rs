use crate::config::Config;
use crate::services::OidcState;
use openidconnect::{core::{CoreClient, CoreProviderMetadata, CoreResponseType}, AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CallbackRequest {
    pub code: String,
    pub state: String,
    pub iss: String,
}

fn get_http_client() -> reqwest::Client {
    reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Something went wrong :(")
}

pub async fn initialize_openid(
    config: &Config,
) -> Result<CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>, Box<dyn std::error::Error>> {
    let issuer_url: IssuerUrl = config.oidc_issuer_url.clone().expect("Missing oidc_issuer_url");
    let http_client = get_http_client();

    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oidc_client_id.clone().unwrap_or_default()),
        None, // No client_secret for public client
    )
        .set_redirect_uri(RedirectUrl::new(config.oidc_redirect_uri.clone().unwrap_or_default())?);

    Ok(client)
}

pub fn generate_auth_url(
    client: &CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>,
) -> (String, CsrfToken, Nonce, PkceCodeVerifier) {
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
        .add_scopes(vec![
            Scope::new("openid".to_string()),
            Scope::new("profile".to_string()),
            Scope::new("email".to_string()),
        ])
        .url();

    (
        auth_url.to_string(),
        csrf_token,
        nonce,
        pkce_verifier,
    )
}

pub async fn exchange_code(
    config: &Config,
    client: &CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>,
    code: String,
    iss: String,
    state: String,
    oidc_state: OidcState
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let expected_issuer = config
        .oidc_issuer_url
        .as_ref()
        .map(|u| u.as_str())
        .unwrap_or(iss.as_str());
    if iss.as_str() != expected_issuer {
        return Err("Issuer invalid".into());
    }
    if oidc_state.state.secret() != state.as_str() {
        return Err("State invalid".into());
    }
    let http_client = get_http_client();
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(oidc_state.pkce_verifier)
        .request_async(&http_client)
        .await?;

    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or("No ID token in response")?;

    let token_claims = id_token
        .claims(
            &client.id_token_verifier(),
            &oidc_state.nonce,
        )
        .map_err(|e| format!("Failed to verify ID token: {}", e))?;

    if let Some(token_nonce) = token_claims.nonce() {
        if token_nonce.secret() != oidc_state.nonce.secret() {
            return Err("Nonce mismatch - potential replay attack!".into());
        }
    } else {
        return Err("No nonce in ID token claims".into());
    }

    let audience = token_claims.audiences();
    let expected_audience = config.oidc_client_id.as_ref().unwrap();
    if !audience.iter().any(|aud| aud.as_str() == expected_audience) {
        return Err("Audience invalid".into());
    }

    let user_id = token_claims.subject().to_string();

    let email = token_claims.email().ok_or("No email in ID token claims")?.to_string();

    Ok((user_id, email))
}