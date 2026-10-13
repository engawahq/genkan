//! Rendering the pages: sign-in, enrolment, errors and notices. Routing and the data behind each
//! page belong to the caller.

use askama::Template;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

use super::assets::{VERSIONS, Versions};
use super::harden;
use super::i18n::{Lang, Messages};

/// A "Continue with …" button for an upstream identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderButton {
    /// Path segment of the provider's routes, for example `github`.
    pub id: &'static str,
    /// Name shown on the button.
    pub label: &'static str,
    /// Icon name (see `templates/icons.html`).
    pub icon: &'static str,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    client: Option<&'a str>,
    subtitle: String,
    login_hint: Option<&'a str>,
    providers: &'a [ProviderButton],
}

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    providers: &'a [ProviderButton],
}

#[derive(Template)]
#[template(path = "notice.html")]
struct NoticePage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    title: &'a str,
    body: &'a str,
}

/// Renders a page that only informs (for example, "account linked").
#[must_use]
pub fn notice_page(lang: Lang, title: &str, body: &str) -> Response {
    let page = NoticePage {
        lang,
        langs: &Lang::ALL,
        m: lang.messages(),
        assets: &VERSIONS,
        title,
        body,
    };
    render(StatusCode::OK, &page)
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    detail: &'a str,
}

/// The page language: `?lang=` (the language switcher), then `Accept-Language`.
#[must_use]
pub fn page_lang(query: Option<&str>, headers: &HeaderMap) -> Lang {
    let explicit = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .find(|(key, _)| key == "lang")
        .map(|(_, value)| value.into_owned());
    Lang::negotiate(explicit.as_deref(), accept_language(headers))
}

/// The `Accept-Language` header, if it is text.
#[must_use]
pub fn accept_language(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
}

fn render(status: StatusCode, page: &impl Template) -> Response {
    let mut response = match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(_error) => {
            tracing::error!(reason = "page_render_failed", "rendering a page failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };
    harden(&mut response);
    response
}

/// Renders the error page shown when an authorization request cannot be trusted enough to
/// redirect (RFC 6749 §4.1.2.1).
#[must_use]
pub fn error_page(lang: Lang, detail: &str) -> Response {
    let page = ErrorPage {
        lang,
        langs: &Lang::ALL,
        m: lang.messages(),
        assets: &VERSIONS,
        detail,
    };
    render(StatusCode::BAD_REQUEST, &page)
}

/// Renders the sign-in page. Without a pending request (`client` is `None`) it explains that
/// there is nothing to sign in to; `providers` adds "Continue with …" buttons.
#[must_use]
pub fn login_page(
    lang: Lang,
    client: Option<&str>,
    login_hint: Option<&str>,
    providers: &[ProviderButton],
) -> Response {
    let m = lang.messages();
    let subtitle = client.map_or_else(
        || m.login_subtitle.to_owned(),
        |c| format!("{} {c}", m.login_continue_to),
    );
    let page = LoginPage {
        lang,
        langs: &Lang::ALL,
        m,
        assets: &VERSIONS,
        client,
        subtitle,
        login_hint,
        providers,
    };
    render(StatusCode::OK, &page)
}

/// Renders the enrolment page, where a setup link or invitation becomes a passkey (or, with
/// `providers`, a linked upstream account).
#[must_use]
pub fn setup_page(lang: Lang, providers: &[ProviderButton]) -> Response {
    let page = SetupPage {
        lang,
        langs: &Lang::ALL,
        m: lang.messages(),
        assets: &VERSIONS,
        providers,
    };
    render(StatusCode::OK, &page)
}
