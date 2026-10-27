// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reassembly of EventSource in-band manifest chunks.
//!
//! The manifest envelope has no emission identifier, so **chunk 0 anchors an
//! emission**: it always (re)starts the partial manifest for its stream, which
//! also covers the sender's `EventTooBig` retry (it halves the chunk size and
//! restarts at chunk 0 with a new `TotalChunks`).  Chunks `1..N` may then
//! arrive in any order (tolerating per-CPU buffer reordering in real-time
//! sessions).  A non-zero chunk with no anchored partial cannot be attributed
//! to an emission and is discarded.
//!
//! Memory and lifetime are bounded by per-manifest, global, idle-time and
//! absolute-age limits.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::envelope::{self, EnvelopeError, ManifestEnvelope};
use super::XxBuildHasher;
use crate::Guid;

/// Maximum size of one reassembled manifest.
pub(crate) const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
/// Maximum `TotalChunks` accepted (bounds the per-partial slot vector).
pub(crate) const MAX_TOTAL_CHUNKS: u16 = 8192;
/// Maximum number of concurrently assembling manifests (all streams).
pub(crate) const MAX_PARTIALS: usize = 32;
/// Maximum bytes buffered across all partial manifests.
pub(crate) const MAX_PARTIAL_BYTES_TOTAL: usize = 32 * 1024 * 1024;
/// A partial is dropped if no chunk arrives for this long.
pub(crate) const PARTIAL_IDLE_TTL: Duration = Duration::from_secs(10);
/// A partial is dropped this long after its chunk 0, regardless of activity.
pub(crate) const PARTIAL_MAX_AGE: Duration = Duration::from_secs(60);

/// Identity of a manifest emission stream: EventSource writes all chunks of
/// one emission from a single thread.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey {
    pub(crate) provider: Guid,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
}

/// Why a chunk was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reject {
    Envelope(EnvelopeError),
    /// Non-zero chunk with no anchored partial for its stream.
    Orphan,
    /// Chunk header disagrees with the anchored emission.
    HeaderMismatch,
    /// The chunk's slot was already filled.
    Duplicate,
    /// `TotalChunks` or accumulated bytes exceed the limits.
    TooLarge,
}

pub(crate) enum ChunkOutcome {
    /// Chunk stored; more chunks are needed.
    Pending,
    /// All chunks received; the concatenated manifest bytes.
    Complete(Vec<u8>),
    Rejected(Reject),
}

/// Result of [`Assembler::add_chunk`].
pub(crate) struct AddResult {
    pub(crate) outcome: ChunkOutcome,
    /// Partial manifests abandoned while handling this chunk (restarted,
    /// rejected, expired, or evicted).
    pub(crate) dropped: u64,
}

struct Partial {
    header: ManifestEnvelope,
    chunks: Vec<Option<Box<[u8]>>>,
    received: u16,
    bytes: usize,
    anchored_at: Instant,
    last_update: Instant,
}

impl Partial {
    fn is_stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_update) > PARTIAL_IDLE_TTL
            || now.saturating_duration_since(self.anchored_at) > PARTIAL_MAX_AGE
    }
}

#[derive(Default)]
pub(crate) struct Assembler {
    partials: HashMap<StreamKey, Partial, XxBuildHasher>,
    total_bytes: usize,
}

impl Assembler {
    pub(crate) fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    /// Feeds one manifest event payload (envelope + chunk bytes).
    pub(crate) fn add_chunk(
        &mut self,
        key: StreamKey,
        user_data: &[u8],
        now: Instant,
    ) -> AddResult {
        let mut dropped = self.sweep(now);

        let reject = |this: &mut Self, dropped: &mut u64, reason: Reject| {
            if this.remove(&key) {
                *dropped += 1;
            }
            ChunkOutcome::Rejected(reason)
        };

        let (env, chunk) = match envelope::parse(user_data) {
            Ok(parsed) => parsed,
            Err(e) => {
                let outcome = reject(self, &mut dropped, Reject::Envelope(e));
                return AddResult { outcome, dropped };
            }
        };

        if env.total_chunks > MAX_TOTAL_CHUNKS || chunk.len() > MAX_MANIFEST_BYTES {
            let outcome = reject(self, &mut dropped, Reject::TooLarge);
            return AddResult { outcome, dropped };
        }

        if env.chunk_number == 0 {
            if self.remove(&key) {
                dropped += 1;
            }

            if env.total_chunks == 1 {
                return AddResult { outcome: ChunkOutcome::Complete(chunk.to_vec()), dropped };
            }

            let mut chunks: Vec<Option<Box<[u8]>>> =
                (0..env.total_chunks).map(|_| None).collect();
            chunks[0] = Some(chunk.into());

            self.total_bytes += chunk.len();
            self.partials.insert(key, Partial {
                header: env,
                chunks,
                received: 1,
                bytes: chunk.len(),
                anchored_at: now,
                last_update: now,
            });

            dropped += self.enforce_caps(&key);
            return AddResult { outcome: ChunkOutcome::Pending, dropped };
        }

        let Some(partial) = self.partials.get_mut(&key) else {
            return AddResult { outcome: ChunkOutcome::Rejected(Reject::Orphan), dropped };
        };

        if !partial.header.same_header(&env) {
            let outcome = reject(self, &mut dropped, Reject::HeaderMismatch);
            return AddResult { outcome, dropped };
        }

        let slot = env.chunk_number as usize;
        if partial.chunks[slot].is_some() {
            let outcome = reject(self, &mut dropped, Reject::Duplicate);
            return AddResult { outcome, dropped };
        }

        if partial.bytes + chunk.len() > MAX_MANIFEST_BYTES {
            let outcome = reject(self, &mut dropped, Reject::TooLarge);
            return AddResult { outcome, dropped };
        }

        partial.chunks[slot] = Some(chunk.into());
        partial.received += 1;
        partial.bytes += chunk.len();
        partial.last_update = now;
        self.total_bytes += chunk.len();

        if partial.received == partial.header.total_chunks {
            let partial = self.partials.remove(&key).expect("partial present");
            self.total_bytes -= partial.bytes;

            let mut manifest = Vec::with_capacity(partial.bytes);
            for chunk in partial.chunks.into_iter().flatten() {
                manifest.extend_from_slice(&chunk);
            }

            return AddResult { outcome: ChunkOutcome::Complete(manifest), dropped };
        }

        dropped += self.enforce_caps(&key);
        AddResult { outcome: ChunkOutcome::Pending, dropped }
    }

    /// Drops partials that exceeded the idle TTL or absolute max age.
    /// Returns the number dropped.
    pub(crate) fn sweep(&mut self, now: Instant) -> u64 {
        if self.partials.is_empty() {
            return 0;
        }

        let before = self.partials.len();
        let mut freed = 0usize;
        self.partials.retain(|_, p| {
            let stale = p.is_stale(now);
            if stale {
                freed += p.bytes;
            }
            !stale
        });
        self.total_bytes -= freed;

        (before - self.partials.len()) as u64
    }

    fn remove(&mut self, key: &StreamKey) -> bool {
        match self.partials.remove(key) {
            Some(p) => {
                self.total_bytes -= p.bytes;
                true
            }
            None => false,
        }
    }

    /// Evicts the least-recently-updated partials (never `keep`) until the
    /// global count and byte limits hold.  Returns the number evicted.
    fn enforce_caps(&mut self, keep: &StreamKey) -> u64 {
        let mut evicted = 0;

        while self.partials.len() > MAX_PARTIALS || self.total_bytes > MAX_PARTIAL_BYTES_TOTAL {
            let oldest = self.partials
                .iter()
                .filter(|(k, _)| *k != keep)
                .min_by_key(|(_, p)| p.last_update)
                .map(|(k, _)| *k);

            match oldest {
                Some(k) => {
                    self.remove(&k);
                    evicted += 1;
                }
                None => break,
            }
        }

        evicted
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.partials.len()
    }

    #[cfg(test)]
    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::envelope::build_chunk;

    fn key(pid: u32, tid: u32) -> StreamKey {
        StreamKey { provider: Guid::from_u128(0xABCD), pid, tid }
    }

    fn complete(r: AddResult) -> Vec<u8> {
        match r.outcome {
            ChunkOutcome::Complete(bytes) => bytes,
            ChunkOutcome::Pending => panic!("expected Complete, got Pending"),
            ChunkOutcome::Rejected(why) => panic!("expected Complete, got {why:?}"),
        }
    }

    fn pending(r: AddResult) {
        assert!(matches!(r.outcome, ChunkOutcome::Pending), "expected Pending");
    }

    fn rejected(r: AddResult) -> Reject {
        match r.outcome {
            ChunkOutcome::Rejected(why) => why,
            _ => panic!("expected Rejected"),
        }
    }

    #[test]
    fn single_chunk_completes_immediately() {
        let mut a = Assembler::default();
        let now = Instant::now();
        assert_eq!(complete(a.add_chunk(key(1, 1), &build_chunk(1, 0, b"abc"), now)), b"abc");
        assert!(a.is_empty());
    }

    #[test]
    fn in_order_and_reverse_order_after_anchor() {
        let now = Instant::now();

        let mut a = Assembler::default();
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, b"aa"), now));
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 1, b"bb"), now));
        assert_eq!(complete(a.add_chunk(key(1, 1), &build_chunk(3, 2, b"cc"), now)), b"aabbcc");
        assert_eq!(a.total_bytes(), 0);

        let mut a = Assembler::default();
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, b"aa"), now));
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 2, b"cc"), now));
        assert_eq!(complete(a.add_chunk(key(1, 1), &build_chunk(3, 1, b"bb"), now)), b"aabbcc");
    }

    #[test]
    fn orphan_nonzero_chunk_is_discarded() {
        let mut a = Assembler::default();
        let now = Instant::now();
        assert_eq!(rejected(a.add_chunk(key(1, 1), &build_chunk(3, 1, b"bb"), now)), Reject::Orphan);
        assert!(a.is_empty());
    }

    #[test]
    fn interleaved_streams_are_independent() {
        let mut a = Assembler::default();
        let now = Instant::now();
        let other_provider = StreamKey { provider: Guid::from_u128(0x1234), pid: 1, tid: 1 };

        pending(a.add_chunk(key(1, 1), &build_chunk(2, 0, b"A0"), now));
        pending(a.add_chunk(key(1, 2), &build_chunk(2, 0, b"B0"), now));
        pending(a.add_chunk(other_provider, &build_chunk(2, 0, b"C0"), now));

        assert_eq!(complete(a.add_chunk(key(1, 2), &build_chunk(2, 1, b"B1"), now)), b"B0B1");
        assert_eq!(complete(a.add_chunk(other_provider, &build_chunk(2, 1, b"C1"), now)), b"C0C1");
        assert_eq!(complete(a.add_chunk(key(1, 1), &build_chunk(2, 1, b"A1"), now)), b"A0A1");
    }

    #[test]
    fn chunk_zero_restarts_with_new_total() {
        // Simulates EventSource's EventTooBig retry: chunk 0 with 2 chunks,
        // then a restart with smaller chunks (3 total).
        let mut a = Assembler::default();
        let now = Instant::now();
        pending(a.add_chunk(key(1, 1), &build_chunk(2, 0, b"xxxx"), now));

        let r = a.add_chunk(key(1, 1), &build_chunk(3, 0, b"ab"), now);
        assert_eq!(r.dropped, 1, "restart abandons the previous partial");
        pending(r);

        pending(a.add_chunk(key(1, 1), &build_chunk(3, 1, b"cd"), now));
        assert_eq!(complete(a.add_chunk(key(1, 1), &build_chunk(3, 2, b"ef"), now)), b"abcdef");
    }

    #[test]
    fn duplicate_and_mismatched_chunks_drop_partial() {
        let now = Instant::now();

        let mut a = Assembler::default();
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, b"aa"), now));
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 1, b"bb"), now));
        let r = a.add_chunk(key(1, 1), &build_chunk(3, 1, b"bb"), now);
        assert_eq!(r.dropped, 1);
        assert_eq!(rejected(r), Reject::Duplicate);
        assert!(a.is_empty());

        let mut a = Assembler::default();
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, b"aa"), now));
        assert_eq!(rejected(a.add_chunk(key(1, 1), &build_chunk(4, 1, b"bb"), now)), Reject::HeaderMismatch);
        assert!(a.is_empty());
    }

    #[test]
    fn invalid_envelope_drops_stream_partial() {
        let mut a = Assembler::default();
        let now = Instant::now();
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, b"aa"), now));

        let mut bad = build_chunk(3, 1, b"bb");
        bad[3] = 0;
        let r = a.add_chunk(key(1, 1), &bad, now);
        assert_eq!(r.dropped, 1);
        assert_eq!(rejected(r), Reject::Envelope(EnvelopeError::BadMagic));
        assert!(a.is_empty());
    }

    #[test]
    fn size_limits_are_enforced() {
        let mut a = Assembler::default();
        let now = Instant::now();
        assert_eq!(
            rejected(a.add_chunk(key(1, 1), &build_chunk(MAX_TOTAL_CHUNKS + 1, 0, b"a"), now)),
            Reject::TooLarge
        );

        let half = vec![b'x'; MAX_MANIFEST_BYTES / 2 + 1];
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, &half), now));
        assert_eq!(rejected(a.add_chunk(key(1, 1), &build_chunk(3, 1, &half), now)), Reject::TooLarge);
        assert!(a.is_empty());
        assert_eq!(a.total_bytes(), 0);
    }

    #[test]
    fn idle_ttl_and_max_age_expire_partials() {
        let start = Instant::now();

        let mut a = Assembler::default();
        pending(a.add_chunk(key(1, 1), &build_chunk(3, 0, b"aa"), start));
        assert_eq!(a.sweep(start + PARTIAL_IDLE_TTL), 0);
        assert_eq!(a.sweep(start + PARTIAL_IDLE_TTL + Duration::from_millis(1)), 1);
        assert_eq!(a.total_bytes(), 0);

        // A trickling stream stays within the idle TTL but hits the max age.
        let mut a = Assembler::default();
        pending(a.add_chunk(key(1, 1), &build_chunk(MAX_TOTAL_CHUNKS, 0, b"a"), start));
        let mut t = start;
        let mut n = 1;
        while t.saturating_duration_since(start) <= PARTIAL_MAX_AGE {
            t += Duration::from_secs(5);
            let r = a.add_chunk(key(1, 1), &build_chunk(MAX_TOTAL_CHUNKS, n, b"a"), t);
            n += 1;
            if t.saturating_duration_since(start) > PARTIAL_MAX_AGE {
                assert_eq!(r.dropped, 1, "partial expired at max age");
                assert_eq!(rejected(r), Reject::Orphan);
            } else {
                pending(r);
            }
        }
    }

    #[test]
    fn global_partial_cap_evicts_oldest() {
        let start = Instant::now();
        let mut a = Assembler::default();

        for i in 0..MAX_PARTIALS as u32 {
            let r = a.add_chunk(key(i, 0), &build_chunk(2, 0, b"a"), start + Duration::from_millis(i as u64));
            assert_eq!(r.dropped, 0);
        }

        let r = a.add_chunk(key(999, 0), &build_chunk(2, 0, b"a"), start + Duration::from_secs(1));
        assert_eq!(r.dropped, 1);
        assert_eq!(a.len(), MAX_PARTIALS);

        // The oldest (pid 0) was evicted; its next chunk is now an orphan.
        assert_eq!(
            rejected(a.add_chunk(key(0, 0), &build_chunk(2, 1, b"b"), start + Duration::from_secs(1))),
            Reject::Orphan
        );
        // The newest survives.
        assert_eq!(complete(a.add_chunk(key(999, 0), &build_chunk(2, 1, b"b"), start + Duration::from_secs(1))), b"ab");
    }
}
