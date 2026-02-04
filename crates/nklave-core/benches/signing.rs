//! Performance benchmarks for signing operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use nklave_core::{BlsKeypair, SigningService, SigningType};

fn bench_bls_sign(c: &mut Criterion) {
    let keypair = BlsKeypair::generate();
    let message = [1u8; 32];

    c.bench_function("bls_sign", |b| {
        b.iter(|| keypair.sign(black_box(&message)))
    });
}

fn bench_bls_keygen(c: &mut Criterion) {
    c.bench_function("bls_keygen", |b| {
        b.iter(|| BlsKeypair::generate())
    });
}

fn bench_block_proposal_signing(c: &mut Criterion) {
    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let service = SigningService::new(vec![keypair]);

    let mut slot = 0u64;

    c.bench_function("block_proposal_sign", |b| {
        b.iter(|| {
            slot += 1;
            let signing_root = [slot as u8; 32];
            service.sign_block_proposal(black_box(&pubkey), black_box(slot), black_box(signing_root))
        })
    });
}

fn bench_attestation_signing(c: &mut Criterion) {
    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let service = SigningService::new(vec![keypair]);

    let mut target_epoch = 0u64;

    c.bench_function("attestation_sign", |b| {
        b.iter(|| {
            target_epoch += 1;
            let source_epoch = target_epoch.saturating_sub(1);
            let signing_root = [target_epoch as u8; 32];
            service.sign_attestation(
                black_box(&pubkey),
                black_box(source_epoch),
                black_box(target_epoch),
                black_box(signing_root),
            )
        })
    });
}

fn bench_generic_signing(c: &mut Criterion) {
    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let service = SigningService::new(vec![keypair]);
    let signing_root = [42u8; 32];

    c.bench_function("generic_sign_randao", |b| {
        b.iter(|| {
            service.sign_generic(
                black_box(&pubkey),
                black_box(SigningType::RandaoReveal),
                black_box(signing_root),
            )
        })
    });
}

fn bench_throughput(c: &mut Criterion) {
    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let service = SigningService::new(vec![keypair]);

    let mut group = c.benchmark_group("signing_throughput");
    group.throughput(Throughput::Elements(1));

    let mut slot = 0u64;
    group.bench_function("block_proposals_per_sec", |b| {
        b.iter(|| {
            slot += 1;
            let signing_root = [slot as u8; 32];
            service.sign_block_proposal(&pubkey, slot, signing_root)
        })
    });

    group.finish();
}

fn bench_slashing_check_overhead(c: &mut Criterion) {
    // Benchmark the overhead of slashing protection checks
    // by comparing raw BLS signing vs full service signing
    let keypair = BlsKeypair::generate();
    let pubkey = keypair.public_key_bytes();
    let service = SigningService::new(vec![keypair.clone()]);
    let message = [1u8; 32];

    let mut group = c.benchmark_group("slashing_overhead");

    group.bench_function("raw_bls_sign", |b| {
        b.iter(|| keypair.sign(black_box(&message)))
    });

    let mut slot = 10000u64;
    group.bench_function("with_slashing_protection", |b| {
        b.iter(|| {
            slot += 1;
            let signing_root = [(slot % 256) as u8; 32];
            service.sign_block_proposal(&pubkey, slot, signing_root)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_bls_sign,
    bench_bls_keygen,
    bench_block_proposal_signing,
    bench_attestation_signing,
    bench_generic_signing,
    bench_throughput,
    bench_slashing_check_overhead,
);

criterion_main!(benches);
