//! Non-cryptographic hashing helpers backed by well-established crates.
//!
//! Each function provides a minimal wrapper around a widely used hashing
//! implementation so Criterion benchmarks can compare their performance without
//! re-implementing the algorithms manually.

use std::hash::{Hash, Hasher};

use adler::adler32_slice;
use crc32fast::hash as crc32_hash;
use crc64fast::Digest as Crc64Digest;
use fnv::FnvHasher;
use highway::{HighwayHash, HighwayHasher, Key};
use metrohash::MetroHash64;
use murmur3::murmur3_32;
use siphasher::sip::SipHasher13;
use twox_hash::XxHash64;

/// Compute the MD5 digest for the provided data.
#[must_use]
pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    let digest = md5::compute(data);
    digest.0
}

/// Compute the Adler-32 checksum for the provided data.
#[must_use]
pub fn adler32(data: &[u8]) -> u32 {
    adler32_slice(data)
}

/// Compute the CRC32 checksum for the provided data using the Castagnoli polynomial.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    crc32_hash(data)
}

/// Compute the CRC64 checksum for the provided data using the ECMA polynomial.
#[must_use]
pub fn crc64(data: &[u8]) -> u64 {
    let mut digest = Crc64Digest::new();
    digest.write(data);
    digest.sum64()
}

/// Compute the 64-bit FNV-1a hash for the provided data.
#[must_use]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hasher = FnvHasher::default();
    hasher.write(data);
    hasher.finish()
}

/// Compute the Murmur3 x86 32-bit hash for the provided data using the supplied seed.
#[must_use]
pub fn murmur3_32_hash(data: &[u8], seed: u32) -> u32 {
    murmur3_32(&mut std::io::Cursor::new(data), seed).expect("cursor read should not fail")
}

/// Compute the 64-bit XXHash for the provided data using the supplied seed.
#[must_use]
pub fn xxhash64(data: &[u8], seed: u64) -> u64 {
    let mut hasher = XxHash64::with_seed(seed);
    hasher.write(data);
    hasher.finish()
}

/// Hash arbitrary data using SipHash(1,3) from the `siphasher` crate.
#[must_use]
pub fn siphash13<T: Hash>(value: &T) -> u64 {
    let mut hasher = SipHasher13::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Compute the CityHash64 digest for the provided data.
#[must_use]
pub fn cityhash64(data: &[u8]) -> u64 {
    cityhasher::hash(data)
}

/// Compute the FarmHash64 fingerprint for the provided data.
#[must_use]
pub fn farmhash64(data: &[u8]) -> u64 {
    farmhash::hash64(data)
}

/// Compute the HighwayHash64 fingerprint for the provided data.
#[must_use]
pub fn highway64(data: &[u8]) -> u64 {
    let key = Key([0, 1, 2, 3]);
    let mut hasher = HighwayHasher::new(key);
    hasher.append(data);
    hasher.finalize64()
}

/// Compute the MetroHash64 digest for the provided data using the supplied seed.
#[must_use]
pub fn metrohash64(data: &[u8], seed: u64) -> u64 {
    let mut hasher = MetroHash64::with_seed(seed);
    hasher.write(data);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOX: &[u8] = b"the quick brown fox jumps over the lazy dog";

    #[test]
    fn md5_known_vectors() {
        assert_eq!(
            md5_digest(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e,
            ]
        );
        assert_eq!(
            md5_digest(FOX),
            [
                0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4,
                0x19, 0xd6,
            ]
        );
    }

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(FOX), 0x414F_A339);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc64_known_vectors() {
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn fnv_known_vectors() {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(FOX), 0x7404_cea1_3ff8_9bb0);
    }

    #[test]
    fn murmur3_known_vectors() {
        assert_eq!(murmur3_32_hash(b"", 0), 0);
        assert_eq!(murmur3_32_hash(b"a", 0), 0x3c25_69b2);
        assert_eq!(murmur3_32_hash(FOX, 0), 0x02de_62ff);
    }

    #[test]
    fn xxhash64_known_vectors() {
        assert_eq!(xxhash64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxhash64(b"a", 0), 0xd24e_c4f1_a98c_6e5b);
        assert_eq!(xxhash64(FOX, 0), 0x9283_fd29_be77_9f93);
    }

    #[test]
    fn siphash_consistency() {
        let val = siphash13(&FOX);
        assert_eq!(val, siphash13(&FOX));
        assert_ne!(val, siphash13(&"different"));
    }

    #[test]
    fn cityhash_consistency() {
        let h1 = cityhash64(FOX);
        let h2 = cityhash64(FOX);
        assert_eq!(h1, h2);
        assert_ne!(h1, cityhash64(b"different"));
    }

    #[test]
    fn farmhash_consistency() {
        let h1 = farmhash64(FOX);
        assert_eq!(h1, farmhash64(FOX));
        assert_ne!(h1, farmhash64(b"different"));
    }

    #[test]
    fn highway_consistency() {
        let h1 = highway64(FOX);
        assert_eq!(h1, highway64(FOX));
        assert_ne!(h1, highway64(b"different"));
    }

    #[test]
    fn metrohash_consistency() {
        let h1 = metrohash64(FOX, 0);
        assert_eq!(h1, metrohash64(FOX, 0));
        assert_ne!(h1, metrohash64(b"different", 0));
    }
}
