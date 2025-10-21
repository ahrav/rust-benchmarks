use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use hash_benchmarks::{
    adler32, cityhash64, crc32, crc64, farmhash64, fnv1a_64, highway64, md5_digest, metrohash64,
    murmur3_32_hash, siphash13, spookyhash64, xxhash64,
};

const DATA_SIZES: &[usize] = &[32, 256, 1024, 4096, 65_536];

fn hash_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashes");

    for &size in DATA_SIZES {
        let payload = generate_payload(size);

        group.bench_with_input(BenchmarkId::new("md5", size), &payload, |b, data| {
            b.iter(|| black_box(md5_digest(data)));
        });

        group.bench_with_input(BenchmarkId::new("adler32", size), &payload, |b, data| {
            b.iter(|| black_box(adler32(data)));
        });

        group.bench_with_input(BenchmarkId::new("crc32", size), &payload, |b, data| {
            b.iter(|| black_box(crc32(data)));
        });

        group.bench_with_input(BenchmarkId::new("crc64", size), &payload, |b, data| {
            b.iter(|| black_box(crc64(data)));
        });

        group.bench_with_input(BenchmarkId::new("fnv1a64", size), &payload, |b, data| {
            b.iter(|| black_box(fnv1a_64(data)));
        });

        group.bench_with_input(BenchmarkId::new("murmur3_32", size), &payload, |b, data| {
            b.iter(|| black_box(murmur3_32_hash(data, 0)));
        });

        group.bench_with_input(BenchmarkId::new("xxhash64", size), &payload, |b, data| {
            b.iter(|| black_box(xxhash64(data, 0)));
        });

        group.bench_with_input(BenchmarkId::new("siphash13", size), &payload, |b, data| {
            b.iter(|| black_box(siphash13(data)));
        });

        group.bench_with_input(BenchmarkId::new("cityhash64", size), &payload, |b, data| {
            b.iter(|| black_box(cityhash64(data)));
        });

        group.bench_with_input(BenchmarkId::new("farmhash64", size), &payload, |b, data| {
            b.iter(|| black_box(farmhash64(data)));
        });

        group.bench_with_input(BenchmarkId::new("highway64", size), &payload, |b, data| {
            b.iter(|| black_box(highway64(data)));
        });

        group.bench_with_input(
            BenchmarkId::new("metrohash64", size),
            &payload,
            |b, data| {
                b.iter(|| black_box(metrohash64(data, 0)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("spookyhash64", size),
            &payload,
            |b, data| {
                b.iter(|| black_box(spookyhash64(data, 0, 0)));
            },
        );
    }

    group.finish();
}

fn generate_payload(size: usize) -> Vec<u8> {
    let mut state = 0x0123_4567_89ab_cdefu64;
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        state = state
            .wrapping_mul(636_413_622_384_679_300_5)
            .wrapping_add(1);
        out.push((state >> 32) as u8);
    }
    out
}

criterion_group!(benches, hash_benchmarks);
criterion_main!(benches);
