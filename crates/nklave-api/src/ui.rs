//! UI asset embedding and serving module.
//!
//! This module embeds the Vue.js frontend at compile time using rust-embed
//! and provides handlers for serving the static assets.

use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

/// Embedded UI assets from the Vue.js build output.
/// The folder path is relative to this crate's Cargo.toml location.
#[derive(RustEmbed)]
#[folder = "ui-dist"]
pub struct UiAssets;

/// Serve a UI asset by path, falling back to index.html for SPA routing.
pub async fn serve_ui(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // If path is empty, serve index.html
    let path = if path.is_empty() { "index.html" } else { path };

    // Try to serve the exact file requested
    if let Some(content) = UiAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .header(header::CACHE_CONTROL, cache_control_for_path(path))
            .body(Body::from(content.data.into_owned()))
            .unwrap();
    }

    // For non-existent paths that look like files (have extension), return 404
    if path.contains('.') && !path.ends_with(".html") {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("Not Found"))
            .unwrap();
    }

    // Fallback to index.html for SPA client-side routing
    match UiAssets::get("index.html") {
        Some(content) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(content.data.into_owned()))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("UI not available"))
            .unwrap(),
    }
}

/// Determine cache control header based on file path.
/// Assets with hash in filename can be cached aggressively.
fn cache_control_for_path(path: &str) -> &'static str {
    // Vite adds content hashes to asset filenames
    if path.starts_with("assets/") {
        // Immutable assets with hashes - cache for 1 year
        "public, max-age=31536000, immutable"
    } else if path == "index.html" {
        // HTML should always be revalidated
        "no-cache"
    } else {
        // Other static files - cache for 1 hour
        "public, max-age=3600"
    }
}

/// Check if the UI assets are available (built and embedded).
pub fn ui_available() -> bool {
    UiAssets::get("index.html").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_control() {
        assert_eq!(cache_control_for_path("index.html"), "no-cache");
        assert_eq!(
            cache_control_for_path("assets/index-abc123.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control_for_path("favicon.ico"), "public, max-age=3600");
    }
}
