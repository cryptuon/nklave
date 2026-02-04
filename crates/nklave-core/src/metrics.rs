//! Metrics for the signing service
//!
//! Provides Prometheus-compatible metrics for monitoring signing operations

use metrics::{counter, gauge, histogram};

/// Metric names
pub mod names {
    pub const SIGNING_REQUESTS_TOTAL: &str = "nklave_signing_requests_total";
    pub const SIGNING_REFUSALS_TOTAL: &str = "nklave_signing_refusals_total";
    pub const SIGNING_LATENCY_SECONDS: &str = "nklave_signing_latency_seconds";
    pub const VALIDATORS_TOTAL: &str = "nklave_validators_total";
    pub const STATE_SEQUENCE: &str = "nklave_state_sequence";
    pub const BLOCKS_SIGNED_TOTAL: &str = "nklave_blocks_signed_total";
    pub const ATTESTATIONS_SIGNED_TOTAL: &str = "nklave_attestations_signed_total";
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
