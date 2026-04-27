//! axum-served web dashboard scaffold for Mini-EDR.
//!
//! This crate owns the static single-page shell for the localhost dashboard and
//! intentionally depends only on `mini-edr-common`. The daemon injects live
//! health JSON at runtime, but the web crate stays presentation-only so the
//! workspace dependency graph remains acyclic per SDD §8.2.

use std::sync::Arc;

use axum::{
    Json, Router,
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse},
    routing::get,
};
use serde_json::Value;

/// Re-export the common crate under a stable module name so future code in this
/// subsystem can share domain types without adding ad-hoc dependency aliases.
pub use mini_edr_common as common;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_CSS: &str = include_str!("../static/app.css");
const APP_JS: &str = include_str!("../static/app.js");

/// Lazily-evaluated JSON provider used by `/health`.
///
/// The daemon supplies a closure so the web crate can stay independent from the
/// daemon's concrete health payload type while still serving live JSON from the
/// same localhost dashboard origin.
pub type HealthProvider = Arc<dyn Fn() -> Value + Send + Sync>;

/// Lazily-evaluated process-tree provider used by `/processes`.
///
/// The daemon owns the mutable tree snapshot, but the web crate serves it from
/// the same origin as the static SPA so the browser never needs cross-origin
/// privileges to populate the drill-down UI.
pub type ProcessTreeProvider = Arc<dyn Fn() -> common::ProcessTreeSnapshot + Send + Sync>;

/// Runtime configuration injected into the dashboard router.
#[derive(Clone)]
pub struct DashboardRouterState {
    health_provider: HealthProvider,
    process_tree_provider: ProcessTreeProvider,
}

impl DashboardRouterState {
    /// Create the scaffold state from a daemon-supplied health closure.
    #[must_use]
    pub const fn new(
        health_provider: HealthProvider,
        process_tree_provider: ProcessTreeProvider,
    ) -> Self {
        Self {
            health_provider,
            process_tree_provider,
        }
    }
}

/// Build the public dashboard router used by the daemon's localhost web port.
///
/// The routing topology deliberately keeps the static SPA shell at `/` and the
/// supporting assets beside it (`/app.css`, `/app.js`) so the operator-facing
/// surface is obvious. The live `/health` JSON stays on the same origin so the
/// browser never needs cross-origin privileges just to render the header badge.
pub fn router(state: &DashboardRouterState) -> Router {
    let health_provider = Arc::clone(&state.health_provider);
    let health_alias_provider = Arc::clone(&state.health_provider);
    let process_tree_provider = Arc::clone(&state.process_tree_provider);
    let process_tree_alias_provider = Arc::clone(&state.process_tree_provider);

    Router::new()
        .route("/", get(index))
        .route("/app.css", get(stylesheet))
        .route("/app.js", get(script))
        .route(
            "/health",
            get(move || {
                let health_provider = Arc::clone(&health_provider);
                async move { (StatusCode::OK, Json((health_provider)())) }
            }),
        )
        .route(
            "/api/health",
            get(move || {
                let health_alias_provider = Arc::clone(&health_alias_provider);
                async move { (StatusCode::OK, Json((health_alias_provider)())) }
            }),
        )
        .route(
            "/processes",
            get(move || {
                let process_tree_provider = Arc::clone(&process_tree_provider);
                async move { (StatusCode::OK, Json((process_tree_provider)())) }
            }),
        )
        .route(
            "/api/processes",
            get(move || {
                let process_tree_alias_provider = Arc::clone(&process_tree_alias_provider);
                async move { (StatusCode::OK, Json((process_tree_alias_provider)())) }
            }),
        )
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        APP_CSS,
    )
}

async fn script() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        APP_JS,
    )
}

#[cfg(test)]
mod tests {
    use super::{APP_JS, DashboardRouterState, router};
    use axum::{
        body,
        http::{Request, StatusCode},
    };
    use mini_edr_common::{
        ProcessDetail, ProcessDetailField, ProcessInfo, ProcessTreeNode, ProcessTreeSnapshot,
    };
    use regex::Regex;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn sample_router() -> axum::Router {
        let state = DashboardRouterState::new(
            Arc::new(|| {
                json!({
                    "state": "Running",
                    "model_hash": "demo-model",
                    "web_port": 8080
                })
            }),
            Arc::new(|| ProcessTreeSnapshot {
                processes: vec![ProcessTreeNode {
                    pid: 4_242,
                    process_name: "demo-shell".to_owned(),
                    binary_path: "/usr/bin/demo-shell".to_owned(),
                    threat_score: Some(0.85),
                    depth: 2,
                    detail: ProcessDetail {
                        ancestry_chain: vec![
                            ProcessInfo {
                                pid: 1,
                                process_name: "systemd".to_owned(),
                                binary_path: "/usr/lib/systemd/systemd".to_owned(),
                            },
                            ProcessInfo {
                                pid: 4_242,
                                process_name: "demo-shell".to_owned(),
                                binary_path: "/usr/bin/demo-shell".to_owned(),
                            },
                        ],
                        feature_vector: vec![ProcessDetailField {
                            label: "entropy".to_owned(),
                            value: "0.850".to_owned(),
                        }],
                        recent_syscalls: vec!["execve ×1".to_owned()],
                        threat_score: Some(0.85),
                        top_features: Vec::new(),
                    },
                    exited: false,
                }],
            }),
        );
        router(&state)
    }

    #[tokio::test]
    async fn root_contains_expected_header_and_assets() {
        let response = sample_router()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router serves root HTML");

        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(
            body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body bytes")
                .to_vec(),
        )
        .expect("utf8 html");

        assert!(html.contains("<title>Mini-EDR</title>"));
        assert!(html.contains("Mini-EDR"));
        assert!(html.contains("aria-label=\"Settings\""));
        assert!(html.contains("process-tree"));
        assert!(html.contains("process-detail"));
        assert!(html.contains("alert-timeline"));
        assert!(html.contains("severity-filter"));
        assert!(html.contains("time-filter"));
        assert!(html.contains("health-tab-button"));
        assert!(html.contains("health-tab-panel"));
        assert!(html.contains("data-metric=\"events-per-second\""));
        assert!(html.contains("data-metric=\"ring-buffer-utilization\""));
        assert!(html.contains("data-metric=\"inference-latency\""));
        assert!(html.contains("data-metric=\"uptime\""));
        assert!(html.contains("data-metric=\"memory\""));
        assert!(html.contains("degraded-badge"));
        assert!(html.contains("No threats detected"));
        assert!(html.contains("/app.css"));
        assert!(html.contains("/app.js"));
    }

    #[tokio::test]
    async fn health_and_process_routes_share_the_same_payloads() {
        let expected = json!({
            "state": "Running",
            "model_hash": "demo-model",
            "web_port": 8080
        });

        for path in ["/health", "/api/health"] {
            let response = sample_router()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(body::Body::empty())
                        .unwrap(),
                )
                .await
                .expect("router serves health alias");

            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = serde_json::from_slice(
                &body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("json bytes"),
            )
            .expect("json payload");
            assert_eq!(payload, expected);
        }

        for path in ["/processes", "/api/processes"] {
            let response = sample_router()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(body::Body::empty())
                        .unwrap(),
                )
                .await
                .expect("router serves process-tree alias");

            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = serde_json::from_slice(
                &body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("json bytes"),
            )
            .expect("json payload");
            assert_eq!(payload["processes"][0]["pid"].as_u64(), Some(4_242));
            assert_eq!(
                payload["processes"][0]["process_name"].as_str(),
                Some("demo-shell")
            );
            assert_eq!(
                payload["processes"][0]["detail"]["recent_syscalls"][0].as_str(),
                Some("execve ×1")
            );
        }
    }

    #[tokio::test]
    async fn static_assets_encode_the_documented_threshold_partitions() {
        let css_response = sample_router()
            .oneshot(
                Request::builder()
                    .uri("/app.css")
                    .body(body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router serves stylesheet");
        let css = String::from_utf8(
            body::to_bytes(css_response.into_body(), usize::MAX)
                .await
                .expect("css bytes")
                .to_vec(),
        )
        .expect("utf8 css");
        assert!(css.contains("--threat-score-low"));
        assert!(css.contains("--threat-score-medium"));
        assert!(css.contains("--threat-score-high"));
        assert!(css.contains("--score-grey"));
        assert!(css.contains("data-threat-band=\"low\""));
        assert!(css.contains("data-threat-band=\"medium\""));
        assert!(css.contains("data-threat-band=\"high\""));
        assert!(css.contains("data-threat-band=\"unscored\""));
        assert!(css.contains(".alert-row[data-severity=\"low\"]"));
        assert!(css.contains(".timeline-filter-bar"));

        let js_response = sample_router()
            .oneshot(
                Request::builder()
                    .uri("/app.js")
                    .body(body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router serves script");
        let js = String::from_utf8(
            body::to_bytes(js_response.into_body(), usize::MAX)
                .await
                .expect("js bytes")
                .to_vec(),
        )
        .expect("utf8 js");
        assert!(js.contains("score < 0.3"));
        assert!(js.contains("score < 0.7"));
        assert!(js.contains("dataset.threatBand"));
        assert!(js.contains("/processes"));
        assert!(js.contains("/api/dashboard/alerts"));
        assert!(js.contains("/api/settings/csrf"));
        assert!(js.contains("/ws"));
        assert!(js.contains("/telemetry/summary"));
        assert!(js.contains("renderActiveTab"));
        assert!(js.contains("refreshTelemetry"));
        assert!(js.contains("medium+"));
        assert!(js.contains("last_30m"));
        assert!(js.contains("textContent"));
        assert!(js.contains("requestAnimationFrame"));
    }

    #[tokio::test]
    async fn static_script_contains_optional_threat_score_null_guards() {
        // Defense-in-depth: scrutiny found that null / absent threat scores were
        // previously treated as high severity and could crash on `.toFixed()`.
        // Keep a regex assertion over the shipped asset so future refactors do
        // not silently delete the explicit unscored branch.
        let unscored_guard =
            Regex::new(r#"if\s*\(!hasFiniteThreatScore\(score\)\)\s*\{\s*return "unscored";\s*\}"#)
                .expect("valid guard regex");

        assert!(unscored_guard.is_match(APP_JS));
        assert!(APP_JS.contains("formatThreatScore(process.threat_score, 2, \"unscored\")"));
        assert!(APP_JS.contains("formatThreatScore(process.detail.threat_score, 3)"));
        assert!(APP_JS.contains("formatThreatScore(alert.threat_score, 3)"));
    }

    #[test]
    fn static_script_contains_incremental_tree_diff_with_stable_keys() {
        // Scrutiny round 1 found the web SPA replacing the whole process tree
        // on every 1 Hz poll, which reset scroll position and broke deep-tree
        // navigation. Keep a source-level assertion over the shipped asset so
        // future refactors preserve the keyed diff/update structure.
        let key_map_regex = Regex::new(
            r"processTree:\s*\{\s*emptyStateEl:\s*null,\s*lastRenderStats:\s*null,\s*rowsByKey:\s*new Map\(\)",
        )
        .expect("valid process-tree key map regex");

        assert!(key_map_regex.is_match(APP_JS));
        assert!(APP_JS.contains("function processStableKey(process)"));
        assert!(APP_JS.contains("treeRoot.insertBefore(row, rowAtTargetIndex ?? null)"));
        assert!(APP_JS.contains("treeRoot.scrollTop = preservedScrollTop"));
        assert!(APP_JS.contains("RENDER_FRAME_BUDGET_MS = 12"));
    }
}
