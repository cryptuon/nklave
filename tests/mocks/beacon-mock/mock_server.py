#!/usr/bin/env python3
"""
Mock Beacon Node for Nklave Integration Testing

Provides minimal Ethereum Beacon API endpoints for testing validator clients
with Nklave as a remote signer.
"""

from flask import Flask, jsonify, request
import time

app = Flask(__name__)

# Mock configuration
GENESIS_TIME = int(time.time()) - 1000000  # Some time in the past
GENESIS_VALIDATORS_ROOT = "0x" + "00" * 32
GENESIS_FORK_VERSION = "0x01017000"
SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12


def current_slot():
    """Calculate current slot based on genesis time."""
    return (int(time.time()) - GENESIS_TIME) // SECONDS_PER_SLOT


def current_epoch():
    """Calculate current epoch."""
    return current_slot() // SLOTS_PER_EPOCH


# Beacon API endpoints

@app.route('/eth/v1/beacon/genesis', methods=['GET'])
def genesis():
    """Return genesis information."""
    return jsonify({
        "data": {
            "genesis_time": str(GENESIS_TIME),
            "genesis_validators_root": GENESIS_VALIDATORS_ROOT,
            "genesis_fork_version": GENESIS_FORK_VERSION
        }
    })


@app.route('/eth/v1/config/spec', methods=['GET'])
def config_spec():
    """Return network specification."""
    return jsonify({
        "data": {
            "SLOTS_PER_EPOCH": str(SLOTS_PER_EPOCH),
            "SECONDS_PER_SLOT": str(SECONDS_PER_SLOT),
            "GENESIS_FORK_VERSION": GENESIS_FORK_VERSION,
            "ALTAIR_FORK_VERSION": "0x02017000",
            "BELLATRIX_FORK_VERSION": "0x03017000",
            "CAPELLA_FORK_VERSION": "0x04017000",
            "DENEB_FORK_VERSION": "0x05017000",
            "ALTAIR_FORK_EPOCH": "0",
            "BELLATRIX_FORK_EPOCH": "0",
            "CAPELLA_FORK_EPOCH": "0",
            "DENEB_FORK_EPOCH": "0"
        }
    })


@app.route('/eth/v1/validator/duties/proposer/<int:epoch>', methods=['GET'])
def proposer_duties(epoch):
    """Return proposer duties for an epoch (empty for mock)."""
    return jsonify({
        "dependent_root": "0x" + "00" * 32,
        "execution_optimistic": False,
        "data": []
    })


@app.route('/eth/v1/validator/duties/attester/<int:epoch>', methods=['POST'])
def attester_duties(epoch):
    """Return attester duties for validators (empty for mock)."""
    return jsonify({
        "dependent_root": "0x" + "00" * 32,
        "execution_optimistic": False,
        "data": []
    })


@app.route('/eth/v1/validator/duties/sync/<int:epoch>', methods=['POST'])
def sync_duties(epoch):
    """Return sync committee duties (empty for mock)."""
    return jsonify({
        "execution_optimistic": False,
        "data": []
    })


@app.route('/eth/v1/beacon/states/head/fork', methods=['GET'])
def state_fork():
    """Return current fork information."""
    return jsonify({
        "data": {
            "previous_version": GENESIS_FORK_VERSION,
            "current_version": "0x05017000",
            "epoch": "0"
        }
    })


@app.route('/eth/v1/node/version', methods=['GET'])
def node_version():
    """Return node version."""
    return jsonify({
        "data": {
            "version": "mock-beacon-node/v0.1.0"
        }
    })


@app.route('/eth/v1/node/syncing', methods=['GET'])
def syncing():
    """Return sync status (always synced for mock)."""
    return jsonify({
        "data": {
            "head_slot": str(current_slot()),
            "sync_distance": "0",
            "is_syncing": False,
            "is_optimistic": False,
            "el_offline": False
        }
    })


@app.route('/eth/v1/beacon/headers/head', methods=['GET'])
def head_header():
    """Return head block header."""
    slot = current_slot()
    return jsonify({
        "data": {
            "root": "0x" + "ab" * 32,
            "canonical": True,
            "header": {
                "message": {
                    "slot": str(slot),
                    "proposer_index": "0",
                    "parent_root": "0x" + "00" * 32,
                    "state_root": "0x" + "11" * 32,
                    "body_root": "0x" + "22" * 32
                },
                "signature": "0x" + "00" * 96
            }
        }
    })


# Block and attestation submission (accept but don't process)

@app.route('/eth/v1/beacon/blocks', methods=['POST'])
def submit_block():
    """Accept block submission."""
    return '', 200


@app.route('/eth/v1/beacon/pool/attestations', methods=['POST'])
def submit_attestations():
    """Accept attestation submission."""
    return '', 200


@app.route('/eth/v1/beacon/pool/sync_committees', methods=['POST'])
def submit_sync_committee():
    """Accept sync committee contribution."""
    return '', 200


# Health check
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"})


if __name__ == '__main__':
    print("Starting Mock Beacon Node on port 5052...")
    app.run(host='0.0.0.0', port=5052)
