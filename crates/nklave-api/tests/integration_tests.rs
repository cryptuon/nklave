//! Integration tests for the full signing flow

use nklave_api::{create_router, AppState};
use nklave_core::{BlsKeypair, SigningService};
use nklave_storage::{Checkpoint, DecisionLog};
use std::sync::Arc;
use tempfile::TempDir;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

fn create_test_state_with_key() -> (Arc<AppState>, [u8; 48]) {
    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let service = SigningService::new(vec![keypair]);
    let state = Arc::new(AppState::new(Arc::new(service)));
    (state, pubkey)
}

fn pubkey_hex(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

#[tokio::test]
async fn test_full_signing_flow_block_proposal() {
    let (state, pubkey) = create_test_state_with_key();
    let app = create_router(state);

    let request_body = serde_json::json!({
        "type": "BLOCK_V2",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "beacon_block": {
            "version": "BELLATRIX",
            "block_header": {
                "slot": "100",
                "proposer_index": "1",
                "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "body_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_hex(&pubkey)))
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(response["signature"].is_string());
    let signature = response["signature"].as_str().unwrap();
    assert!(signature.starts_with("0x"));
    assert_eq!(signature.len(), 194); // 0x + 192 hex chars (96 bytes)
}

#[tokio::test]
async fn test_full_signing_flow_attestation() {
    let (state, pubkey) = create_test_state_with_key();
    let app = create_router(state);

    let request_body = serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "attestation": {
            "slot": "100",
            "index": "0",
            "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "source": {
                "epoch": "10",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "target": {
                "epoch": "11",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_hex(&pubkey)))
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_double_proposal_rejected() {
    let (state, pubkey) = create_test_state_with_key();
    let pubkey_str = pubkey_hex(&pubkey);

    // First request should succeed
    let request_body1 = serde_json::json!({
        "type": "BLOCK_V2",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "beacon_block": {
            "version": "BELLATRIX",
            "block_header": {
                "slot": "100",
                "proposer_index": "1",
                "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "body_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let app1 = create_router(state.clone());
    let response1 = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                .header("content-type", "application/json")
                .body(Body::from(request_body1.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::OK);

    // Second request with different signing root for same slot should fail
    let request_body2 = serde_json::json!({
        "type": "BLOCK_V2",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000002",
        "beacon_block": {
            "version": "BELLATRIX",
            "block_header": {
                "slot": "100",
                "proposer_index": "1",
                "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "body_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let app2 = create_router(state);
    let response2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                .header("content-type", "application/json")
                .body(Body::from(request_body2.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_double_vote_rejected() {
    let (state, pubkey) = create_test_state_with_key();
    let pubkey_str = pubkey_hex(&pubkey);

    // First attestation
    let request_body1 = serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "attestation": {
            "slot": "100",
            "index": "0",
            "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "source": {
                "epoch": "10",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "target": {
                "epoch": "11",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let app1 = create_router(state.clone());
    let response1 = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                .header("content-type", "application/json")
                .body(Body::from(request_body1.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::OK);

    // Second attestation with same target epoch but different signing root
    let request_body2 = serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000002",
        "attestation": {
            "slot": "100",
            "index": "0",
            "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "source": {
                "epoch": "10",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "target": {
                "epoch": "11",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000001"
            }
        }
    });

    let app2 = create_router(state);
    let response2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                .header("content-type", "application/json")
                .body(Body::from(request_body2.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_surround_vote_rejected() {
    let (state, pubkey) = create_test_state_with_key();
    let pubkey_str = pubkey_hex(&pubkey);

    // First attestation (source=5, target=10)
    let request_body1 = serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "attestation": {
            "slot": "100",
            "index": "0",
            "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "source": {
                "epoch": "5",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "target": {
                "epoch": "10",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let app1 = create_router(state.clone());
    let response1 = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                .header("content-type", "application/json")
                .body(Body::from(request_body1.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::OK);

    // Second attestation (source=3, target=12) surrounds the first
    let request_body2 = serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000002",
        "attestation": {
            "slot": "100",
            "index": "0",
            "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "source": {
                "epoch": "3",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "target": {
                "epoch": "12",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let app2 = create_router(state);
    let response2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                .header("content-type", "application/json")
                .body(Body::from(request_body2.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_list_public_keys_returns_managed_keys() {
    let (state, pubkey) = create_test_state_with_key();
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let keys: Vec<String> = serde_json::from_slice(&body).unwrap();

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], pubkey_hex(&pubkey));
}

#[tokio::test]
async fn test_randao_signing() {
    let (state, pubkey) = create_test_state_with_key();
    let app = create_router(state);

    let request_body = serde_json::json!({
        "type": "RANDAO_REVEAL",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "0"
            },
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "randao_reveal": {
            "epoch": "100"
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/eth2/sign/{}", pubkey_hex(&pubkey)))
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_crash_recovery_with_checkpoint() {
    let temp_dir = TempDir::new().unwrap();
    let checkpoint_path = temp_dir.path().join("checkpoint.json");
    let log_path = temp_dir.path().join("decisions.log");

    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let pubkey_str = pubkey_hex(&pubkey);

    // Phase 1: Create signing operations and save checkpoint
    {
        let service = SigningService::new(vec![keypair.clone()]);
        let decision_log = DecisionLog::open(&log_path).unwrap();
        let state = Arc::new(AppState::with_full_config(
            Arc::new(service),
            temp_dir.path().to_path_buf(),
            "test".to_string(),
            decision_log,
            checkpoint_path.clone(),
        ));

        let app = create_router(state.clone());

        // Sign a block proposal at slot 100
        let request_body = serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x01000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "beacon_block": {
                "version": "BELLATRIX",
                "block_header": {
                    "slot": "100",
                    "proposer_index": "1",
                    "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "body_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Save checkpoint
        let integrity = state.signing_service.integrity();
        let validators = state.signing_service.validator_states();
        let checkpoint = Checkpoint::new(&integrity, validators);
        checkpoint.save(&checkpoint_path).unwrap();
    }

    // Phase 2: Simulate restart - load from checkpoint and verify protection
    {
        let checkpoint = Checkpoint::load(&checkpoint_path).unwrap();
        assert_eq!(checkpoint.sequence, 1);

        let integrity = checkpoint.restore_integrity();
        let service = SigningService::with_state(
            vec![keypair.clone()],
            checkpoint.validators,
            integrity,
        );

        let decision_log = DecisionLog::open(&log_path).unwrap();
        let state = Arc::new(AppState::with_full_config(
            Arc::new(service),
            temp_dir.path().to_path_buf(),
            "test".to_string(),
            decision_log,
            checkpoint_path.clone(),
        ));

        let app = create_router(state);

        // Try to sign different block at same slot - should fail
        let request_body = serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x01000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000002",
            "beacon_block": {
                "version": "BELLATRIX",
                "block_header": {
                    "slot": "100",
                    "proposer_index": "1",
                    "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "body_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/eth2/sign/{}", pubkey_str))
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Rejected - double proposal at slot 100
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }
}
