use axum::{
    extract::State,
    http::{header, HeaderValue, Method},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ferrous_dns_api::{create_api_router_with_openapi, metrics_routes, AppState};
use ferrous_dns_api_pihole::{create_pihole_router_with_openapi, PiholeAppState};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tracing::info;
use utoipa::openapi::OpenApi;
use utoipa_scalar::{Scalar, Servable};

use super::web_tls;

pub async fn start_doh_server(
    bind_addr: SocketAddr,
    handler: Arc<DnsServerHandler>,
) -> anyhow::Result<()> {
    info!(
        bind_address = %bind_addr,
        endpoint = format!("http://{}/dns-query", bind_addr),
        "Starting DoH server (DNS-over-HTTPS, RFC 8484)"
    );

    let app = Router::new()
        .route(
            "/dns-query",
            get(crate::server::doh::dns_query_handler).post(crate::server::doh::dns_query_handler),
        )
        .layer(axum::Extension(handler));

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("DoH server ready on {}", bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn start_web_server(
    bind_addr: SocketAddr,
    ferrous_state: AppState,
    pihole_state: Option<PiholeAppState>,
    cors_allowed_origins: &[String],
    metrics_enabled: bool,
    doh_handler: Option<Arc<DnsServerHandler>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<()> {
    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };

    if pihole_state.is_some() {
        info!(
            bind_address = %bind_addr,
            dashboard_url = format!("{}://{}", scheme, bind_addr),
            ferrous_api_url = format!("{}://{}/ferrous/api", scheme, bind_addr),
            pihole_api_url = format!("{}://{}/api", scheme, bind_addr),
            "Starting web server (Pi-hole compat mode)"
        );
    } else {
        info!(
            bind_address = %bind_addr,
            dashboard_url = format!("{}://{}", scheme, bind_addr),
            api_url = format!("{}://{}/api", scheme, bind_addr),
            "Starting web server"
        );
    }

    let app = create_app(
        ferrous_state,
        pihole_state,
        cors_allowed_origins,
        metrics_enabled,
        doh_handler,
    );

    if let Some(tls_cfg) = tls_config {
        info!("Web server started successfully (HTTPS)");
        web_tls::start_https_web_server(bind_addr, app, tls_cfg).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("Web server started successfully");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins == ["*"] {
        return CorsLayer::permissive();
    }
    build_strict_cors(allowed_origins)
}

fn build_strict_cors(allowed_origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

/// An API's routes plus its `/openapi.json` spec and Scalar UI at `/docs`.
fn api_branch(router: Router, spec: OpenApi) -> Router {
    let json = spec.clone();
    Router::new()
        .route(
            "/openapi.json",
            get(move || {
                let json = json.clone();
                async move { Json(json) }
            }),
        )
        .merge(Router::from(Scalar::with_url("/docs", spec)))
        .merge(router)
}

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "application/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml; charset=utf-8";

/// Mounts files embedded from `web/static`, one `url => (file, content type)`
/// row each, so a route cannot drift from the file it serves.
macro_rules! static_files {
    ($router:expr, { $($url:literal => ($file:literal, $mime:expr)),* $(,)? }) => {
        $router$(
            .route(
                $url,
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, $mime)],
                        include_str!(concat!("../../../../web/static/", $file)),
                    )
                }),
            )
        )*
    };
}

/// The web app. The Pi-hole API, when `pihole_state` is given, takes `/api`
/// and moves the Ferrous API to `/ferrous/api`.
fn create_app(
    ferrous_state: AppState,
    pihole_state: Option<PiholeAppState>,
    cors_allowed_origins: &[String],
    metrics_enabled: bool,
    doh_handler: Option<Arc<DnsServerHandler>>,
) -> Router {
    let pihole_compat = pihole_state.is_some();
    // Clone before the state is moved into the API router so the bare
    // `/metrics` route can carry its own copy.
    let metrics_state = metrics_enabled.then(|| ferrous_state.clone());
    let (ferrous_router, ferrous_openapi) = create_api_router_with_openapi(ferrous_state);
    let ferrous_branch = api_branch(ferrous_router, ferrous_openapi);

    let router = match pihole_state {
        Some(state) => {
            let (pihole_router, pihole_openapi) = create_pihole_router_with_openapi(state);
            Router::new()
                .nest("/api", api_branch(pihole_router, pihole_openapi))
                .nest("/ferrous/api", ferrous_branch)
        }
        None => Router::new().nest("/api", ferrous_branch),
    };

    let router = router.route(
        "/ferrous-config.js",
        get(ferrous_config_js_handler).with_state(pihole_compat),
    );
    let mut app = static_files!(router, {
        "/static/shared.css" => ("shared.css", CSS),
        "/static/shared.js" => ("shared.js", JS),
        "/static/logo.svg" => ("logo.svg", SVG),
        "/static/dashboard.css" => ("dashboard.css", CSS),
        "/static/dashboard.js" => ("dashboard.js", JS),
        "/static/queries.css" => ("queries.css", CSS),
        "/static/queries.js" => ("queries.js", JS),
        "/static/cache-control.css" => ("cache-control.css", CSS),
        "/static/cache-control.js" => ("cache-control.js", JS),
        "/static/dnssec.css" => ("dnssec.css", CSS),
        "/static/dnssec.js" => ("dnssec.js", JS),
        "/static/clients.css" => ("clients.css", CSS),
        "/static/clients.js" => ("clients.js", JS),
        "/static/groups.css" => ("groups.css", CSS),
        "/static/groups.js" => ("groups.js", JS),
        "/static/local-dns-settings.css" => ("local-dns-settings.css", CSS),
        "/static/local-dns-settings.js" => ("local-dns-settings.js", JS),
        "/static/settings.css" => ("settings.css", CSS),
        "/static/settings.js" => ("settings.js", JS),
        "/static/dns-filter.css" => ("dns-filter.css", CSS),
        "/static/dns-filter.js" => ("dns-filter.js", JS),
        "/static/block-services.css" => ("block-services.css", CSS),
        "/static/block-services.js" => ("block-services.js", JS),
        "/static/login.css" => ("login.css", CSS),
        "/static/login.js" => ("login.js", JS),
        "/" => ("index.html", HTML),
        "/login.html" => ("login.html", HTML),
        "/dashboard.html" => ("dashboard.html", HTML),
        "/queries.html" => ("queries.html", HTML),
        "/cache-control.html" => ("cache-control.html", HTML),
        "/dnssec.html" => ("dnssec.html", HTML),
        "/clients.html" => ("clients.html", HTML),
        "/groups.html" => ("groups.html", HTML),
        "/local-dns-settings.html" => ("local-dns-settings.html", HTML),
        "/settings.html" => ("settings.html", HTML),
        "/dns-filter.html" => ("dns-filter.html", HTML),
        "/block-services.html" => ("block-services.html", HTML),
    })
    .layer(CompressionLayer::new().gzip(true))
    .layer(build_cors_layer(cors_allowed_origins));

    // Bare unauthenticated `/metrics`, mounted outside the `/api` nest (and thus
    // outside the auth layer) per the Prometheus scrape convention.
    if let Some(state) = metrics_state {
        app = app.merge(metrics_routes(state));
    }

    if let Some(handler) = doh_handler {
        app = app
            .route(
                "/dns-query",
                get(crate::server::doh::dns_query_handler)
                    .post(crate::server::doh::dns_query_handler),
            )
            .layer(axum::Extension(handler));
    }

    app
}

/// Returns a small JS snippet that sets `window.FERROUS_API_BASE` and
/// `window.FERROUS_VERSION` at runtime.
///
/// The HTMLs are compiled into the binary via `include_str!` and cannot be
/// patched at runtime, so the frontend discovers the correct API prefix here.
///
/// - `pihole_compat = false` → `window.FERROUS_API_BASE = "/api";`
/// - `pihole_compat = true`  → `window.FERROUS_API_BASE = "/ferrous/api";`
async fn ferrous_config_js_handler(State(pihole_compat): State<bool>) -> impl IntoResponse {
    let api_base = if pihole_compat {
        "/ferrous/api"
    } else {
        "/api"
    };
    let version = env!("CARGO_PKG_VERSION");
    let body =
        format!(r#"window.FERROUS_API_BASE = "{api_base}";window.FERROUS_VERSION = "{version}";"#);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
}
