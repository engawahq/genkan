//! `GET /login`, `GET /setup` and the embedded assets: the routes in front of the page rendering
//! in [`genkan_ui`].

use std::sync::Arc;

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use genkan_core::clock::Clock;
use genkan_oauth::AuthorizationServer;
use genkan_oauth::endpoints::{FLOW_COOKIE, open_flow};
use genkan_store::{Directory, GrantStore};
use genkan_ui::pages::{ProviderButton, login_page, page_lang, setup_page};

use crate::cookie;
use crate::upstream::provider::Kind;

type Shared<D, G, C> = (Arc<AuthorizationServer<D, G, C>>, Arc<[ProviderButton]>);

/// The page routes and `/assets/{name}`. `providers` are the upstream providers offered.
pub fn router<D: Directory, G: GrantStore, C: Clock>(
    server: Arc<AuthorizationServer<D, G, C>>,
    providers: &[Kind],
) -> Router {
    let buttons: Arc<[ProviderButton]> = providers.iter().map(|kind| kind.button()).collect();
    Router::new()
        .route("/login", get(login::<D, G, C>))
        .route("/setup", get(setup::<D, G, C>))
        .with_state((server, buttons))
        .merge(genkan_ui::assets::router())
}

async fn login<D: Directory, G: GrantStore, C: Clock>(
    State((server, providers)): State<Shared<D, G, C>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let lang = page_lang(query.as_deref(), &headers);
    let flow = cookie(&headers, FLOW_COOKIE).and_then(|sealed| open_flow(&server, sealed));
    let client = match &flow {
        None => None,
        Some(flow) => match server.directory.client(&flow.request.client_id).await {
            Ok(Some(client)) => Some(client.display_name.unwrap_or(client.id)),
            Ok(None) => None,
            Err(error) => {
                tracing::error!(%error, "client lookup failed");
                None
            }
        },
    };
    // Elevation needs a passkey, so upstream providers are not offered for it, and the page
    // says that the application is asking for elevated access.
    let elevated = flow.as_ref().is_some_and(|f| f.request.is_elevated());
    let login_hint = flow.and_then(|f| f.request.login_hint);
    login_page(
        lang,
        client.as_deref(),
        server.lifetimes.elevated_token.filter(|_| elevated),
        login_hint.as_deref(),
        if elevated { &[] } else { &providers },
    )
}

async fn setup<D: Directory, G: GrantStore, C: Clock>(
    State((_, providers)): State<Shared<D, G, C>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    setup_page(page_lang(query.as_deref(), &headers), &providers)
}
