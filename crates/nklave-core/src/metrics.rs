//! Metrics for the signing service
//!
//! Provides Prometheus-compatible metrics for monitoring signing operations

use metrics::{counter, gauge, histogram};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global startup timestamp for uptime calculation
static STARTUP_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Metric names
pub mod names {
    // Signing operation metrics
    pub const SIGNING_REQUESTS_TOTAL: &str = "nklave_signing_requests_total";
    pub const SIGNING_REFUSALS_TOTAL: &str = "nklave_signing_refusals_total";
    pub const SIGNING_LATENCY_SECONDS: &str = "nklave_signing_latency_seconds";
    pub const BLOCKS_SIGNED_TOTAL: &str = "nklave_blocks_signed_total";
    pub const ATTESTATIONS_SIGNED_TOTAL: &str = "nklave_attestations_signed_total";

    // State metrics
    pub const VALIDATORS_TOTAL: &str = "nklave_validators_total";
    pub const STATE_SEQUENCE: &str = "nklave_state_sequence";

    // Operational metrics
    pub const STARTUP_TIMESTAMP_SECONDS: &str = "nklave_startup_timestamp_seconds";
    pub const UPTIME_SECONDS: &str = "nklave_uptime_seconds";
    pub const CHECKPOINT_AGE_SECONDS: &str = "nklave_checkpoint_age_seconds";
    pub const LAST_CHECKPOINT_SEQUENCE: &str = "nklave_last_checkpoint_sequence";

    // Per-validator watermarks
    pub const LAST_SIGNED_SLOT: &str = "nklave_last_signed_slot";
    pub const LAST_SIGNED_TARGET_EPOCH: &str = "nklave_last_signed_target_epoch";

    // Key management metrics
    pub const KEYS_RELOAD_TOTAL: &str = "nklave_keys_reload_total";
    pub const KEYS_LOAD_DURATION_SECONDS: &str = "nklave_keys_load_duration_seconds";

    // Replication metrics
    pub const REPLICATION_LAG_SEQUENCES: &str = "nklave_replication_lag_sequences";
    pub const NODE_ROLE: &str = "nklave_node_role";
}

/// Record a successful signing request
pub fn record_signing_success(request_type: &str, validator: &str) {
    counter!(names::SIGNING_REQUESTS_TOTAL, "type" => request_type.to_string(), "status" => "success", "validator" => validator.to_string())
        .increment(1);
}

/// Record a refused signing request
pub fn record_signing_refusal(request_type: &str, reason: &str, validator: &str) {
    counter!(names::SIGNING_REQUESTS_TOTAL, "type" => request_type.to_string(), "status" => "refused", "validator" => validator.to_string())
        .increment(1);
    counter!(names::SIGNING_REFUSALS_TOTAL, "type" => request_type.to_string(), "reason" => reason.to_string(), "validator" => validator.to_string())
        .increment(1);
}

/// Record signing latency
pub fn record_signing_latency(request_type: &str, latency_seconds: f64) {
    histogram!(names::SIGNING_LATENCY_SECONDS, "type" => request_type.to_string())
        .record(latency_seconds);
}

/// Set the number of managed validators
pub fn set_validators_count(count: usize) {
    gauge!(names::VALIDATORS_TOTAL).set(count as f64);
}

/// Set the current state sequence number
pub fn set_state_sequence(sequence: u64) {
    gauge!(names::STATE_SEQUENCE).set(sequence as f64);
}

/// Record a block signed
pub fn record_block_signed(validator: &str) {
    counter!(names::BLOCKS_SIGNED_TOTAL, "validator" => validator.to_string()).increment(1);
}

/// Record an attestation signed
pub fn record_attestation_signed(validator: &str) {
    counter!(names::ATTESTATIONS_SIGNED_TOTAL, "validator" => validator.to_string()).increment(1);
}

/// Initialize startup metrics (call once at startup)
pub fn init_startup_metrics() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    STARTUP_TIMESTAMP.store(now, Ordering::SeqCst);
    gauge!(names::STARTUP_TIMESTAMP_SECONDS).set(now as f64);
}

/// Update uptime metric (call periodically or on request)
pub fn update_uptime() {
    let startup = STARTUP_TIMESTAMP.load(Ordering::SeqCst);
    if startup > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let uptime = now.saturating_sub(startup);
        gauge!(names::UPTIME_SECONDS).set(uptime as f64);
    }
}

/// Record checkpoint age (time since last checkpoint)
pub fn set_checkpoint_age(age_seconds: u64) {
    gauge!(names::CHECKPOINT_AGE_SECONDS).set(age_seconds as f64);
}

/// Record last checkpoint sequence number
pub fn set_last_checkpoint_sequence(sequence: u64) {
    gauge!(names::LAST_CHECKPOINT_SEQUENCE).set(sequence as f64);
}

/// Record last signed slot for a validator
pub fn set_last_signed_slot(validator: &str, slot: u64) {
    gauge!(names::LAST_SIGNED_SLOT, "validator" => validator.to_string()).set(slot as f64);
}

/// Record last signed target epoch for a validator
pub fn set_last_signed_target_epoch(validator: &str, epoch: u64) {
    gauge!(names::LAST_SIGNED_TARGET_EPOCH, "validator" => validator.to_string()).set(epoch as f64);
}

/// Record a key reload operation
pub fn record_keys_reload(new_keys: usize) {
    counter!(names::KEYS_RELOAD_TOTAL).increment(1);
    gauge!(names::VALIDATORS_TOTAL).set(new_keys as f64);
}

/// Record key loading duration
pub fn record_keys_load_duration(duration_seconds: f64) {
    histogram!(names::KEYS_LOAD_DURATION_SECONDS).record(duration_seconds);
}

/// Set the replication lag in sequences (for passive nodes)
pub fn set_replication_lag(lag_sequences: u64) {
    gauge!(names::REPLICATION_LAG_SEQUENCES).set(lag_sequences as f64);
}

/// Set the current node role (primary, passive, standalone, promoting)
pub fn set_node_role(role: &str) {
    // We use a labeled gauge where the value is 1 for the active role
    // First reset all roles to 0
    gauge!(names::NODE_ROLE, "role" => "primary").set(0.0);
    gauge!(names::NODE_ROLE, "role" => "passive").set(0.0);
    gauge!(names::NODE_ROLE, "role" => "standalone").set(0.0);
    gauge!(names::NODE_ROLE, "role" => "promoting").set(0.0);
    // Set the current role to 1
    gauge!(names::NODE_ROLE, "role" => role.to_string()).set(1.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_names() {
        // Just verify the names are valid
        assert!(names::SIGNING_REQUESTS_TOTAL.starts_with("nklave_"));
        assert!(names::SIGNING_REFUSALS_TOTAL.starts_with("nklave_"));
        assert!(names::SIGNING_LATENCY_SECONDS.starts_with("nklave_"));
    }
}
