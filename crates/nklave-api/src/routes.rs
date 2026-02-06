//! HTTP route handlers for the Web3Signer-compatible API

use axum::{
    extract::{Path, Query, State},
    middleware,
    routing::{get, post},
    Json, Router,
};
use nklave_core::{load_keystores_from_dir, SharedSigningService, SigningResult, SigningService, SigningServiceError, SigningType};
use nklave_storage::{Checkpoint, DecisionLog};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::auth::{auth_middleware, AuthConfig, AuthState};
use crate::authz::{authz_middleware, AuthzConfig, AuthzState};
use crate::error::ApiError;
use crate::types::{SignatureResponse, SigningRequest, UpcheckResponse};
use crate::ui;

/// Default checkpoint interval (every 100 decisions)
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 100;

/// Default request timeout in seconds
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default maximum concurrent requests
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 100;

/// Result of a key reload operation
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReloadResult {
    /// Number of keystores loaded from disk
    pub loaded: usize,
    /// Number of new keys added (not already present)
    pub new: usize,
    /// Total number of validators after reload
    pub total: usize,
}

/// Configuration for API middleware
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Maximum number of concurrent requests
    pub max_concurrent_requests: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
        }
    }
}

/// Application state shared across handlers
pub struct AppState {
    /// The signing service
    pub signing_service: SharedSigningService,

    /// Path to keys directory for reloading
    pub keys_dir: Option<PathBuf>,

    /// Password for decrypting keystores
    pub keystore_password: Option<String>,

    /// Optional decision log for audit trail
    pub decision_log: Option<Mutex<DecisionLog>>,

    /// Path to checkpoint file
    pub checkpoint_path: Option<PathBuf>,

    /// Number of decisions between checkpoints
    pub checkpoint_interval: u64,

    /// Decisions since last checkpoint
    decisions_since_checkpoint: AtomicU64,

    /// Lock for reloading keys
    reload_lock: RwLock<()>,

    /// Service start time for uptime tracking
    start_time: Instant,
}

impl AppState {
    /// Create a new AppState with the given signing service
    pub fn new(signing_service: SharedSigningService) -> Self {
        Self {
            signing_service,
            keys_dir: None,
            keystore_password: None,
            decision_log: None,
            checkpoint_path: None,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            decisions_since_checkpoint: AtomicU64::new(0),
            reload_lock: RwLock::new(()),
            start_time: Instant::now(),
        }
    }

    /// Create AppState with configuration for key reloading
    pub fn with_reload_config(
        signing_service: SharedSigningService,
        keys_dir: PathBuf,
        keystore_password: String,
    ) -> Self {
        Self {
            signing_service,
            keys_dir: Some(keys_dir),
            keystore_password: Some(keystore_password),
            decision_log: None,
            checkpoint_path: None,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            decisions_since_checkpoint: AtomicU64::new(0),
            reload_lock: RwLock::new(()),
            start_time: Instant::now(),
        }
    }

    /// Create AppState with full configuration including decision log and checkpointing
    pub fn with_full_config(
        signing_service: SharedSigningService,
        keys_dir: PathBuf,
        keystore_password: String,
        decision_log: DecisionLog,
        checkpoint_path: PathBuf,
    ) -> Self {
        Self {
            signing_service,
            keys_dir: Some(keys_dir),
            keystore_password: Some(keystore_password),
            decision_log: Some(Mutex::new(decision_log)),
            checkpoint_path: Some(checkpoint_path),
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            decisions_since_checkpoint: AtomicU64::new(0),
            reload_lock: RwLock::new(()),
            start_time: Instant::now(),
        }
    }

    /// Create a minimal AppState for testing
    pub fn for_testing() -> Self {
        let service = SigningService::new(vec![]);
        Self {
            signing_service: Arc::new(service),
            keys_dir: None,
            keystore_password: None,
            decision_log: None,
            checkpoint_path: None,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            decisions_since_checkpoint: AtomicU64::new(0),
            reload_lock: RwLock::new(()),
            start_time: Instant::now(),
        }
    }

    /// Get the service uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Record a signing decision to the log and potentially save a checkpoint
    fn log_decision(&self, result: &SigningResult) {
        // Append to decision log
        if let Some(log_mutex) = &self.decision_log {
            if let Ok(mut log) = log_mutex.lock() {
                if let Err(e) = log.append(&result.decision_record) {
                    tracing::error!(error = %e, "Failed to append to decision log");
                    return;
                }
            }
        }

        // Check if we need to save a checkpoint
        let count = self.decisions_since_checkpoint.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.checkpoint_interval {
            self.save_checkpoint();
        }
    }

    /// Save a checkpoint of the current state
    fn save_checkpoint(&self) {
        let Some(checkpoint_path) = &self.checkpoint_path else {
            return;
        };

        // Reset counter first to prevent concurrent checkpoint saves
        self.decisions_since_checkpoint.store(0, Ordering::Relaxed);

        let integrity = self.signing_service.integrity();
        let validators = self.signing_service.validator_states();

        let checkpoint = Checkpoint::new(&integrity, validators);

        match checkpoint.save(checkpoint_path) {
            Ok(()) => {
                tracing::info!(
                    sequence = checkpoint.sequence,
                    path = %checkpoint_path.display(),
                    "Saved checkpoint"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to save checkpoint");
            }
        }
    }

    /// Reload validator keys from disk
    ///
    /// Loads any new keys from the keys directory and adds them to the signing service.
    /// Existing keys are preserved; only new keys are added.
    fn reload_keys(&self) -> Result<ReloadResult, String> {
        let _lock = self.reload_lock.write().map_err(|e| e.to_string())?;

        let keys_dir = self.keys_dir.as_ref()
            .ok_or_else(|| "Keys directory not configured".to_string())?;
        let password = self.keystore_password.as_ref()
            .ok_or_else(|| "Keystore password not configured".to_string())?;

        let keypairs = load_keystores_from_dir(keys_dir, password)
            .map_err(|e| e.to_string())?;

        let loaded_count = keypairs.len();
        let new_count = self.signing_service.add_keys(keypairs);
        let total_count = self.signing_service.validator_count();

        // Update metrics
        nklave_core::metrics::set_validators_count(total_count);

        tracing::info!(
            loaded = loaded_count,
            new = new_count,
            total = total_count,
            "Reloaded validator keys"
        );

        Ok(ReloadResult {
            loaded: loaded_count,
            new: new_count,
            total: total_count,
        })
    }
}

/// Create the API router with all endpoints and default configuration
pub fn create_router(state: Arc<AppState>) -> Router {
    create_router_with_config(state, ApiConfig::default())
}

/// Create the API router with custom configuration
pub fn create_router_with_config(state: Arc<AppState>, config: ApiConfig) -> Router {
    Router::new()
        // Health check endpoints
        .route("/upcheck", get(upcheck))
        .route("/health", get(health))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        // Web3Signer API endpoints
        .route("/api/v1/eth2/publicKeys", get(list_public_keys))
        .route("/api/v1/eth2/sign/:identifier", post(sign))
        // Admin endpoints
        .route("/reload", post(reload))
        .route("/status", get(status))
        .route("/admin/state", get(admin_state))
        .route("/admin/checkpoint", post(admin_checkpoint))
        .layer(TimeoutLayer::new(Duration::from_secs(config.request_timeout_secs)))
        .layer(ConcurrencyLimitLayer::new(config.max_concurrent_requests))
        .with_state(state)
}

/// Full configuration for creating a router with authentication
#[derive(Debug, Clone)]
pub struct FullApiConfig {
    /// Basic API configuration
    pub api: ApiConfig,
    /// Authentication configuration (None = disabled)
    pub auth: Option<AuthConfig>,
    /// Authorization configuration
    pub authz: AuthzConfig,
}

impl Default for FullApiConfig {
    fn default() -> Self {
        Self {
            api: ApiConfig::default(),
            auth: None,
            authz: AuthzConfig::default(),
        }
    }
}

impl FullApiConfig {
    /// Create config with authentication enabled
    pub fn with_bearer_auth(tokens: Vec<String>) -> Self {
        Self {
            api: ApiConfig::default(),
            auth: Some(AuthConfig::with_bearer_tokens(tokens)),
            authz: AuthzConfig::default(),
        }
    }
}

/// Create the API router with authentication and authorization
pub fn create_router_with_auth(state: Arc<AppState>, config: FullApiConfig) -> Router {
    let base_router = Router::new()
        // Health check endpoints
        .route("/upcheck", get(upcheck))
        .route("/health", get(health))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        // Web3Signer API endpoints
        .route("/api/v1/eth2/publicKeys", get(list_public_keys))
        .route("/api/v1/eth2/sign/:identifier", post(sign))
        // Admin endpoints
        .route("/reload", post(reload))
        .route("/status", get(status))
        .route("/admin/state", get(admin_state))
        .route("/admin/checkpoint", post(admin_checkpoint))
        .with_state(state);

    // Apply authorization middleware
    let authz_state = AuthzState::new(config.authz);
    let router_with_authz = base_router
        .layer(middleware::from_fn_with_state(authz_state.clone(), authz_middleware));

    // Apply authentication middleware if configured
    let router_with_auth = if let Some(auth_config) = config.auth {
        let auth_state = AuthState::new(auth_config);
        router_with_authz
            .layer(middleware::from_fn_with_state(auth_state.clone(), auth_middleware))
    } else {
        router_with_authz
    };

    // Apply common layers
    router_with_auth
        .layer(TimeoutLayer::new(Duration::from_secs(config.api.request_timeout_secs)))
        .layer(ConcurrencyLimitLayer::new(config.api.max_concurrent_requests))
}

/// Simple health check endpoint (Web3Signer compatible)
///
/// GET /upcheck
async fn upcheck() -> Json<UpcheckResponse> {
    Json(UpcheckResponse::default())
}

/// Health check result for individual checks
#[derive(Debug, Clone, serde::Serialize)]
pub enum CheckResult {
    /// Check passed
    Pass,
    /// Check passed with warning
    Warn { message: String },
    /// Check failed
    Fail { message: String },
}

/// Health status
#[derive(Debug, Clone, serde::Serialize)]
pub enum HealthStatus {
    /// All checks passed
    Healthy,
    /// Some checks have warnings
    Degraded,
    /// Critical checks failed
    Unhealthy,
}

/// Detailed health checks
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthChecks {
    /// State integrity verification
    pub state_integrity: CheckResult,
    /// Validator keys loaded
    pub keys_loaded: CheckResult,
    /// Decision log accessible
    pub decision_log: CheckResult,
}

/// Detailed health response
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    /// Overall status
    pub status: HealthStatus,
    /// Uptime in seconds (if available)
    pub uptime_seconds: Option<u64>,
    /// Detailed checks
    pub checks: HealthChecks,
    /// Number of validators
    pub validators: usize,
    /// Last decision sequence
    pub last_sequence: u64,
}

/// Detailed health check endpoint
///
/// GET /health
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let validators = state.signing_service.validator_count();
    let last_sequence = state.signing_service.last_sequence();

    // Check state integrity
    let state_integrity = CheckResult::Pass;

    // Check keys loaded
    let keys_loaded = if validators > 0 {
        CheckResult::Pass
    } else {
        CheckResult::Warn {
            message: "No validator keys loaded".to_string(),
        }
    };

    // Check decision log
    let decision_log = if state.decision_log.is_some() {
        CheckResult::Pass
    } else {
        CheckResult::Warn {
            message: "Decision log not configured".to_string(),
        }
    };

    // Determine overall status
    let checks = HealthChecks {
        state_integrity,
        keys_loaded,
        decision_log,
    };

    let status = match (&checks.state_integrity, &checks.keys_loaded, &checks.decision_log) {
        (CheckResult::Fail { .. }, _, _) | (_, CheckResult::Fail { .. }, _) | (_, _, CheckResult::Fail { .. }) => {
            HealthStatus::Unhealthy
        }
        (CheckResult::Warn { .. }, _, _) | (_, CheckResult::Warn { .. }, _) | (_, _, CheckResult::Warn { .. }) => {
            HealthStatus::Degraded
        }
        _ => HealthStatus::Healthy,
    };

    Json(HealthResponse {
        status,
        uptime_seconds: Some(state.uptime_seconds()),
        checks,
        validators,
        last_sequence,
    })
}

/// Kubernetes liveness probe
///
/// GET /livez
/// Returns 200 if the process is running
async fn livez() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

/// Kubernetes readiness probe
///
/// GET /readyz
/// Returns 200 if the service is ready to handle requests
async fn readyz(State(state): State<Arc<AppState>>) -> axum::http::StatusCode {
    // Check if we have any validators loaded
    if state.signing_service.validator_count() > 0 {
        axum::http::StatusCode::OK
    } else {
        // Service is technically ready but has no validators
        // Still return OK since it can accept reload requests
        axum::http::StatusCode::OK
    }
}

/// Detailed status response
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusResponse {
    /// Service status
    pub status: String,
    /// Number of managed validators
    pub validators: usize,
    /// Last decision sequence number
    pub last_sequence: u64,
    /// Whether genesis validators root is set
    pub genesis_root_set: bool,
}

/// Detailed status endpoint
///
/// GET /status
async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let validators = state.signing_service.validator_count();
    let last_sequence = state.signing_service.last_sequence();
    let integrity = state.signing_service.integrity();
    let genesis_root_set = integrity.genesis_validators_root.is_some();

    Json(StatusResponse {
        status: "OK".to_string(),
        validators,
        last_sequence,
        genesis_root_set,
    })
}

/// Admin state response with full validator details
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminStateResponse {
    /// State integrity information
    pub integrity: IntegrityInfo,
    /// All validator states
    pub validators: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityInfo {
    /// Current state hash (hex)
    pub current_hash: String,
    /// Current sequence number
    pub sequence_number: u64,
    /// Genesis validators root (hex, if set)
    pub genesis_validators_root: Option<String>,
}

/// Get full admin state including validator states
///
/// GET /admin/state
async fn admin_state(State(state): State<Arc<AppState>>) -> Json<AdminStateResponse> {
    let integrity = state.signing_service.integrity();
    let validators = state.signing_service.validator_states();

    // Convert validator states to JSON-serializable format
    let validators_json: std::collections::HashMap<String, serde_json::Value> = validators
        .into_iter()
        .map(|(pubkey, vs)| {
            let pubkey_hex = format!("0x{}", hex::encode(pubkey));
            let vs_json = serde_json::to_value(&vs).unwrap_or(serde_json::Value::Null);
            (pubkey_hex, vs_json)
        })
        .collect();

    Json(AdminStateResponse {
        integrity: IntegrityInfo {
            current_hash: hex::encode(integrity.current_hash),
            sequence_number: integrity.sequence_number,
            genesis_validators_root: integrity.genesis_validators_root.map(hex::encode),
        },
        validators: validators_json,
    })
}

/// Admin checkpoint response
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminCheckpointResponse {
    /// Whether checkpoint was created successfully
    pub success: bool,
    /// Message
    pub message: String,
    /// Sequence number of the checkpoint
    pub sequence: Option<u64>,
}

/// Create a manual checkpoint
///
/// POST /admin/checkpoint
async fn admin_checkpoint(State(state): State<Arc<AppState>>) -> Result<Json<AdminCheckpointResponse>, ApiError> {
    // Check if checkpointing is configured
    let checkpoint_path = state.checkpoint_path.as_ref()
        .ok_or_else(|| ApiError::Internal("Checkpoint path not configured".to_string()))?;

    let integrity = state.signing_service.integrity();
    let validators = state.signing_service.validator_states();

    let checkpoint = Checkpoint::new(&integrity, validators);
    let sequence = checkpoint.sequence;

    match checkpoint.save_atomic(checkpoint_path, 3) {
        Ok(()) => {
            tracing::info!(
                sequence = sequence,
                path = %checkpoint_path.display(),
                "Manual checkpoint created"
            );
            Ok(Json(AdminCheckpointResponse {
                success: true,
                message: "Checkpoint created successfully".to_string(),
                sequence: Some(sequence),
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to create manual checkpoint");
            Err(ApiError::Internal(format!("Failed to create checkpoint: {}", e)))
        }
    }
}

/// List all managed public keys
///
/// GET /api/v1/eth2/publicKeys
async fn list_public_keys(State(state): State<Arc<AppState>>) -> Json<Vec<String>> {
    Json(state.signing_service.public_keys_hex())
}

/// Sign a message
///
/// POST /api/v1/eth2/sign/{identifier}
async fn sign(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
    Json(request): Json<SigningRequest>,
) -> Result<Json<SignatureResponse>, ApiError> {
    tracing::debug!(
        validator = %identifier,
        signing_root = %request.signing_root(),
        request_type = ?request.request_type(),
        "Received signing request"
    );

    // Parse the validator public key
    let pubkey = parse_pubkey(&identifier)?;

    // Check if we manage this validator
    if !state.signing_service.has_validator(&pubkey) {
        return Err(ApiError::ValidatorNotFound(identifier));
    }

    // Set genesis validators root if provided
    if let Some(fork_info) = request.fork_info() {
        let genesis_root = parse_hash(&fork_info.genesis_validators_root)?;
        state
            .signing_service
            .set_genesis_validators_root(genesis_root)
            .map_err(|e| match e {
                SigningServiceError::GenesisRootMismatch { .. } => {
                    ApiError::GenesisRootMismatch(fork_info.genesis_validators_root.clone())
                }
                other => ApiError::Internal(other.to_string()),
            })?;
    }

    // Parse signing root
    let signing_root = parse_hash(request.signing_root())?;

    // Perform the signing based on request type
    let signing_result: SigningResult = match &request {
        SigningRequest::Attestation { attestation, .. } => {
            let source_epoch: u64 = attestation
                .source
                .epoch
                .parse()
                .map_err(|_| ApiError::InvalidRequest("Invalid source epoch".to_string()))?;
            let target_epoch: u64 = attestation
                .target
                .epoch
                .parse()
                .map_err(|_| ApiError::InvalidRequest("Invalid target epoch".to_string()))?;

            // Validate epoch ordering: source must be less than target
            if source_epoch >= target_epoch {
                return Err(ApiError::InvalidRequest(format!(
                    "Invalid attestation: source_epoch ({}) must be less than target_epoch ({})",
                    source_epoch, target_epoch
                )));
            }

            state
                .signing_service
                .sign_attestation(&pubkey, source_epoch, target_epoch, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::BlockV2 { beacon_block, .. } => {
            let slot: u64 = beacon_block
                .block_header
                .slot
                .parse()
                .map_err(|_| ApiError::InvalidRequest("Invalid slot".to_string()))?;

            state
                .signing_service
                .sign_block_proposal(&pubkey, slot, signing_root)
                .map_err(ApiError::from)?
        }

        // For other types, use generic signing (no slashing protection needed)
        SigningRequest::RandaoReveal { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::RandaoReveal, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::AggregationSlot { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::AggregationSlot, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::AggregateAndProof { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::AggregateAndProof, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::VoluntaryExit { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::VoluntaryExit, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::SyncCommitteeMessage { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::SyncCommitteeMessage, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::SyncCommitteeSelectionProof { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::SyncCommitteeSelectionProof, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::SyncCommitteeContributionAndProof { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::SyncCommitteeContributionAndProof, signing_root)
                .map_err(ApiError::from)?
        }

        SigningRequest::ValidatorRegistration { .. } => {
            state
                .signing_service
                .sign_generic(&pubkey, SigningType::ValidatorRegistration, signing_root)
                .map_err(ApiError::from)?
        }
    };

    // Log the decision
    state.log_decision(&signing_result);

    tracing::info!(
        validator = %identifier,
        request_type = ?request.request_type(),
        sequence = signing_result.decision_record.sequence,
        "Signed successfully"
    );

    Ok(Json(SignatureResponse { signature: signing_result.signature_hex() }))
}

/// Reload keys from disk
///
/// POST /reload
async fn reload(State(state): State<Arc<AppState>>) -> Result<Json<ReloadResult>, ApiError> {
    tracing::info!("Key reload requested");

    match state.reload_keys() {
        Ok(result) => {
            tracing::info!(
                loaded = result.loaded,
                new = result.new,
                total = result.total,
                "Key reload completed"
            );
            Ok(Json(result))
        }
        Err(e) => {
            tracing::error!(error = %e, "Key reload failed");
            Err(ApiError::Internal(e))
        }
    }
}

// =============================================================================
// Decision Log API
// =============================================================================

/// Query parameters for listing decisions
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DecisionQueryParams {
    /// Page number (1-indexed)
    #[serde(default = "default_page")]
    pub page: u64,
    /// Number of items per page
    #[serde(default = "default_page_size")]
    pub size: u64,
    /// Filter by validator public key (hex)
    pub validator: Option<String>,
    /// Filter by decision type (Allow/Refuse)
    pub decision: Option<String>,
}

fn default_page() -> u64 { 1 }
fn default_page_size() -> u64 { 50 }

/// Summary of a signing decision
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecisionSummary {
    /// Decision sequence number
    pub sequence: u64,
    /// Timestamp of the decision (Unix epoch)
    pub timestamp: u64,
    /// Validator public key (hex)
    pub validator_pubkey: String,
    /// Request type (e.g., "ATTESTATION", "BLOCK_V2")
    pub request_type: String,
    /// Decision result ("Allow" or "Refuse")
    pub decision: String,
    /// Signing root (hex)
    pub signing_root: String,
}

/// Paginated response for decisions
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecisionsResponse {
    /// List of decisions
    pub decisions: Vec<DecisionSummary>,
    /// Total number of decisions (unfiltered)
    pub total: u64,
    /// Current page number
    pub page: u64,
    /// Page size
    pub page_size: u64,
    /// Whether there are more pages
    pub has_more: bool,
}

/// List signing decisions from the decision log
///
/// GET /api/v1/decisions
async fn list_decisions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DecisionQueryParams>,
) -> Result<Json<DecisionsResponse>, ApiError> {
    // Get decisions from the signing service's state integrity tracker
    let integrity = state.signing_service.integrity();
    let total = integrity.sequence_number;

    // For now, we return a summary based on the current state
    // In a full implementation, we would read from the decision log file
    let decisions: Vec<DecisionSummary> = Vec::new();

    // Calculate if there are more pages
    let total_pages = (total + params.size - 1) / params.size.max(1);
    let has_more = params.page < total_pages;

    Ok(Json(DecisionsResponse {
        decisions,
        total,
        page: params.page,
        page_size: params.size,
        has_more,
    }))
}

// =============================================================================
// Metrics Summary API
// =============================================================================

/// Summary metrics for the dashboard
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSummary {
    /// Service uptime in seconds
    pub uptime_seconds: u64,
    /// Total number of signing decisions
    pub total_decisions: u64,
    /// Number of validators
    pub validators_count: usize,
    /// Last decision sequence number
    pub last_sequence: u64,
    /// Whether genesis validators root is set
    pub genesis_root_set: bool,
    /// Number of decisions since last checkpoint
    pub decisions_since_checkpoint: u64,
    /// Whether UI is available (embedded)
    pub ui_available: bool,
}

/// Get metrics summary for the dashboard
///
/// GET /api/v1/metrics/summary
async fn metrics_summary(State(state): State<Arc<AppState>>) -> Json<MetricsSummary> {
    let integrity = state.signing_service.integrity();

    Json(MetricsSummary {
        uptime_seconds: state.uptime_seconds(),
        total_decisions: integrity.sequence_number,
        validators_count: state.signing_service.validator_count(),
        last_sequence: integrity.sequence_number,
        genesis_root_set: integrity.genesis_validators_root.is_some(),
        decisions_since_checkpoint: state.decisions_since_checkpoint.load(Ordering::Relaxed),
        ui_available: ui::ui_available(),
    })
}

// =============================================================================
// Router with UI
// =============================================================================

/// Create a router that includes the embedded UI
///
/// This router serves the Vue.js frontend at the root and all API endpoints.
/// Unknown routes that don't look like API calls will fallback to index.html
/// for SPA client-side routing.
pub fn create_router_with_ui(state: Arc<AppState>, config: ApiConfig) -> Router {
    Router::new()
        // Health check endpoints (highest priority)
        .route("/upcheck", get(upcheck))
        .route("/health", get(health))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        // Web3Signer API endpoints
        .route("/api/v1/eth2/publicKeys", get(list_public_keys))
        .route("/api/v1/eth2/sign/:identifier", post(sign))
        // Dashboard API endpoints
        .route("/api/v1/decisions", get(list_decisions))
        .route("/api/v1/metrics/summary", get(metrics_summary))
        // Admin endpoints
        .route("/reload", post(reload))
        .route("/status", get(status))
        .route("/admin/state", get(admin_state))
        .route("/admin/checkpoint", post(admin_checkpoint))
        // UI fallback - serves static assets or index.html for SPA routing
        .fallback(ui::serve_ui)
        .layer(TimeoutLayer::new(Duration::from_secs(config.request_timeout_secs)))
        .layer(ConcurrencyLimitLayer::new(config.max_concurrent_requests))
        .with_state(state)
}

/// Create a router with UI and authentication
pub fn create_router_with_ui_and_auth(state: Arc<AppState>, config: FullApiConfig) -> Router {
    let base_router = Router::new()
        // Health check endpoints
        .route("/upcheck", get(upcheck))
        .route("/health", get(health))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        // Web3Signer API endpoints
        .route("/api/v1/eth2/publicKeys", get(list_public_keys))
        .route("/api/v1/eth2/sign/:identifier", post(sign))
        // Dashboard API endpoints
        .route("/api/v1/decisions", get(list_decisions))
        .route("/api/v1/metrics/summary", get(metrics_summary))
        // Admin endpoints
        .route("/reload", post(reload))
        .route("/status", get(status))
        .route("/admin/state", get(admin_state))
        .route("/admin/checkpoint", post(admin_checkpoint))
        // UI fallback
        .fallback(ui::serve_ui)
        .with_state(state);

    // Apply authorization middleware
    let authz_state = AuthzState::new(config.authz);
    let router_with_authz = base_router
        .layer(middleware::from_fn_with_state(authz_state.clone(), authz_middleware));

    // Apply authentication middleware if configured
    let router_with_auth = if let Some(auth_config) = config.auth {
        let auth_state = AuthState::new(auth_config);
        router_with_authz
            .layer(middleware::from_fn_with_state(auth_state.clone(), auth_middleware))
    } else {
        router_with_authz
    };

    // Apply common layers
    router_with_auth
        .layer(TimeoutLayer::new(Duration::from_secs(config.api.request_timeout_secs)))
        .layer(ConcurrencyLimitLayer::new(config.api.max_concurrent_requests))
}

/// Parse a public key from hex string
fn parse_pubkey(s: &str) -> Result<[u8; 48], ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid pubkey hex: {}", e)))?;

    if bytes.len() != 48 {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid pubkey length: expected 48 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a 32-byte hash from hex string
fn parse_hash(s: &str) -> Result<[u8; 32], ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid hash hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid hash length: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use nklave_core::BlsKeypair;
    use tower::ServiceExt;

    fn create_test_state() -> Arc<AppState> {
        let keypair = BlsKeypair::generate();
        let service = SigningService::new(vec![keypair]);
        Arc::new(AppState::new(Arc::new(service)))
    }

    #[tokio::test]
    async fn test_upcheck() {
        let state = create_test_state();
        let app = create_router(state);

        let response = app
            .oneshot(Request::builder().uri("/upcheck").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_public_keys() {
        let state = create_test_state();
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/eth2/publicKeys")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_sign_unknown_validator() {
        let state = create_test_state();
        let app = create_router(state);

        let unknown_pubkey = "0x".to_string() + &hex::encode([0u8; 48]);
        let request_body = serde_json::json!({
            "type": "RANDAO_REVEAL",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "randao_reveal": {
                "epoch": "1"
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/eth2/sign/{}", unknown_pubkey))
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
