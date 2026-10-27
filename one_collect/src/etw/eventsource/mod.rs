// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! .NET `EventSource` in-band manifest support for [`TdhDecoder`].
//!
//! Default-mode (manifest) EventSource providers do not register their
//! manifest with the OS; instead they emit it **in-band** as chunked events
//! (`Id 0xFFFE`, `Opcode 0xFE`, `Task 0xFFFE`) whenever an ETW session enables
//! them, on capture-state requests, and on dispose.  This module:
//!
//! 1. reassembles those chunks per emitting `(provider, pid, tid)` stream
//!    ([`assembler`]),
//! 2. parses the completed XML ([`manifest`]), and
//! 3. stores the result so later payload events can be decoded
//!    ([`InbandManifestStore`]).
//!
//! ## Per-process binding
//!
//! Different processes can run different builds of the same EventSource
//! (same GUID, different layouts).  Manifests are therefore bound per
//! `(provider GUID, process ID)`, and interned by content so identical
//! manifests (the common case) share one [`ManifestId`] and one set of cached
//! schemas.  When a process has no binding of its own, the provider's manifest
//! is used only if *every* bound process agrees on it **and** the OS has no
//! registered manifest for the event (any process can emit manifest chunks
//! under any provider GUID, so a fallback must never override a registered
//! schema); conflicting manifests are never guessed between.
//!
//! [`TdhDecoder`]: crate::etw::tdh::TdhDecoder

pub(crate) mod assembler;
pub(crate) mod envelope;
pub(crate) mod manifest;

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::time::Instant;

use tracing::{debug, warn};
use twox_hash::XxHash64;

use crate::Guid;
use crate::etw::tdh::InbandManifestStats;
use assembler::{Assembler, ChunkOutcome, Reject, StreamKey};
use manifest::{EventDef, ProviderManifest};

pub(crate) type XxBuildHasher = BuildHasherDefault<XxHash64>;

/// `EVENT_DESCRIPTOR.Id` of an EventSource manifest chunk event.
pub(crate) const MANIFEST_EVENT_ID: u16 = 0xFFFE;
/// `EVENT_DESCRIPTOR.Opcode` of an EventSource manifest chunk event.
pub(crate) const MANIFEST_EVENT_OPCODE: u8 = 0xFE;
/// `EVENT_DESCRIPTOR.Task` of an EventSource manifest chunk event.
pub(crate) const MANIFEST_EVENT_TASK: u16 = 0xFFFE;

/// Maximum number of `(provider, pid)` bindings (LRU-evicted).
pub(crate) const MAX_PROCESS_BINDINGS: usize = 4096;
/// Maximum number of distinct manifest contents retained.
pub(crate) const MAX_DISTINCT_MANIFESTS: usize = 256;
/// Maximum total raw bytes of retained manifests.
pub(crate) const MAX_STORED_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

/// Returns `true` for the reserved descriptor of an EventSource manifest
/// chunk event.
pub(crate) fn is_manifest_descriptor(id: u16, opcode: u8, task: u16) -> bool {
    id == MANIFEST_EVENT_ID && opcode == MANIFEST_EVENT_OPCODE && task == MANIFEST_EVENT_TASK
}

/// Identifier of one distinct, interned manifest content.  Never reused.
pub(crate) type ManifestId = u32;

/// How a payload event's in-band manifest was found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// The emitting process sent this manifest itself.
    Bound(ManifestId),
    /// The emitting process has no manifest of its own; every bound process
    /// of the provider agrees on this one.
    Fallback(ManifestId),
}

impl Resolved {
    pub(crate) fn manifest(self) -> ManifestId {
        match self {
            Self::Bound(id) | Self::Fallback(id) => id,
        }
    }
}

struct Interned {
    guid: Guid,
    hash: u64,
    manifest: ProviderManifest,
    bytes: Box<[u8]>,
    /// Number of `(provider, pid)` bindings referencing this manifest.
    refcount: u32,
}

struct Binding {
    manifest: ManifestId,
    last_used: u64,
}

#[derive(Default)]
pub(crate) struct InbandManifestStore {
    assembler: Assembler,
    manifests: HashMap<ManifestId, Interned, XxBuildHasher>,
    by_hash: HashMap<(Guid, u64), Vec<ManifestId>, XxBuildHasher>,
    by_process: HashMap<(Guid, u32), Binding, XxBuildHasher>,
    /// Distinct manifests currently bound by at least one process, per GUID.
    by_provider: HashMap<Guid, Vec<ManifestId>, XxBuildHasher>,
    next_id: ManifestId,
    tick: u64,
    stored_bytes: usize,
    stats: InbandManifestStats,
    /// Manifests freed since the last [`Self::take_freed`]; the decoder must
    /// purge their cached schemas.
    freed: Vec<ManifestId>,
    /// Providers already warned about, to rate-limit `warn!` output.
    warned: std::collections::HashSet<Guid, XxBuildHasher>,
}

impl InbandManifestStore {
    pub(crate) fn stats(&self) -> InbandManifestStats {
        self.stats
    }

    /// `true` while any partial manifest is being assembled.
    pub(crate) fn has_partials(&self) -> bool {
        !self.assembler.is_empty()
    }

    /// Feeds one manifest chunk event; installs the manifest when complete.
    pub(crate) fn ingest_chunk(
        &mut self,
        provider: Guid,
        pid: u32,
        tid: u32,
        user_data: &[u8],
        now: Instant,
    ) {
        self.stats.chunks += 1;

        let key = StreamKey { provider, pid, tid };
        let result = self.assembler.add_chunk(key, user_data, now);
        self.stats.partials_dropped += result.dropped;

        match result.outcome {
            ChunkOutcome::Pending => {
                debug!(pid, tid, "EventSource manifest chunk accepted");
            }
            ChunkOutcome::Complete(bytes) => {
                self.stats.manifests_completed += 1;
                debug!(pid, tid, bytes = bytes.len(), "EventSource manifest reassembled");
                self.install(provider, pid, bytes);
            }
            ChunkOutcome::Rejected(Reject::Orphan) => {
                self.stats.orphan_chunks += 1;
                debug!(pid, tid, "EventSource manifest chunk without chunk 0 discarded");
            }
            ChunkOutcome::Rejected(Reject::Envelope(error)) => {
                self.stats.envelope_errors += 1;
                self.warn_once(provider, || warn!(pid, tid, ?error, "invalid EventSource manifest envelope"));
            }
            ChunkOutcome::Rejected(reason) => {
                // Duplicate / HeaderMismatch / TooLarge: the partial was
                // abandoned and is already counted in `partials_dropped`.
                self.warn_once(provider, || warn!(pid, tid, ?reason, "EventSource manifest assembly dropped"));
            }
        }
    }

    /// Drops expired partial manifests.
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.stats.partials_dropped += self.assembler.sweep(now);
    }

    /// Resolves the manifest to use for a payload event, if that manifest
    /// defines `(id, version)`.
    ///
    /// Returns [`Resolved::Bound`] when the emitting process sent the
    /// manifest itself, or [`Resolved::Fallback`] when the process has no
    /// binding and every bound process of the provider agrees on one
    /// manifest.  A fallback must not override an OS-registered manifest:
    /// any process can emit manifest chunks under any provider GUID.
    pub(crate) fn resolve(
        &mut self,
        provider: Guid,
        pid: u32,
        id: u16,
        version: u8,
    ) -> Option<Resolved> {
        if self.by_process.is_empty() {
            return None;
        }

        let resolved = match self.by_process.get_mut(&(provider, pid)) {
            Some(binding) => {
                self.tick += 1;
                binding.last_used = self.tick;
                Resolved::Bound(binding.manifest)
            }
            None => match self.by_provider.get(&provider).map(Vec::as_slice) {
                Some([only]) => Resolved::Fallback(*only),
                _ => return None,
            },
        };

        self.manifests
            .get(&resolved.manifest())
            .filter(|m| m.manifest.events.contains_key(&(id, version)))
            .map(|_| resolved)
    }

    /// Returns the provider name and event definition for a resolved event.
    pub(crate) fn event(
        &self,
        manifest: ManifestId,
        id: u16,
        version: u8,
    ) -> Option<(&str, &EventDef)> {
        let interned = self.manifests.get(&manifest)?;
        let event = interned.manifest.events.get(&(id, version))?;
        Some((interned.manifest.name.as_str(), event))
    }

    /// Takes the IDs of manifests freed since the last call.
    pub(crate) fn take_freed(&mut self) -> Vec<ManifestId> {
        std::mem::take(&mut self.freed)
    }

    fn install(&mut self, provider: Guid, pid: u32, bytes: Vec<u8>) {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&bytes);
        let hash = hasher.finish();
        self.install_hashed(provider, pid, bytes, hash);
    }

    /// Interns `bytes` (by hash, confirmed by byte equality) and binds the
    /// emitting process to it.  Split from [`Self::install`] so tests can
    /// force hash collisions.
    fn install_hashed(&mut self, provider: Guid, pid: u32, bytes: Vec<u8>, hash: u64) {
        let existing = self.by_hash
            .get(&(provider, hash))
            .and_then(|ids| ids.iter().copied().find(|id| {
                self.manifests.get(id).is_some_and(|m| *m.bytes == *bytes)
            }));

        let id = match existing {
            Some(id) => {
                debug!(pid, manifest = id, "identical EventSource manifest re-sent");
                id
            }
            None => {
                let manifest = match manifest::parse(&bytes, &provider) {
                    Ok(m) => m,
                    Err(error) => {
                        self.stats.xml_errors += 1;
                        self.warn_once(provider, || warn!(pid, %error, "EventSource manifest rejected"));
                        return;
                    }
                };

                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.stats.manifests_interned += 1;
                self.stored_bytes += bytes.len();
                debug!(
                    pid,
                    manifest = id,
                    provider_name = %manifest.name,
                    events = manifest.events.len(),
                    "EventSource manifest interned"
                );

                self.by_hash.entry((provider, hash)).or_default().push(id);
                self.manifests.insert(id, Interned {
                    guid: provider,
                    hash,
                    manifest,
                    bytes: bytes.into_boxed_slice(),
                    refcount: 0,
                });
                id
            }
        };

        self.bind((provider, pid), id);
        self.enforce_caps((provider, pid));
    }

    fn bind(&mut self, key: (Guid, u32), id: ManifestId) {
        self.tick += 1;
        let tick = self.tick;

        let previous = match self.by_process.get_mut(&key) {
            Some(binding) if binding.manifest == id => {
                binding.last_used = tick;
                return;
            }
            Some(binding) => {
                let old = binding.manifest;
                binding.manifest = id;
                binding.last_used = tick;
                Some(old)
            }
            None => {
                self.by_process.insert(key, Binding { manifest: id, last_used: tick });
                None
            }
        };

        self.incref(id);
        if let Some(old) = previous {
            debug!(pid = key.1, old, new = id, "EventSource process rebound to new manifest");
            self.decref(old, false);
        }
    }

    fn incref(&mut self, id: ManifestId) {
        if let Some(m) = self.manifests.get_mut(&id) {
            m.refcount += 1;
            if m.refcount == 1 {
                self.by_provider.entry(m.guid).or_default().push(id);
            }
        }
    }

    fn decref(&mut self, id: ManifestId, evicting: bool) {
        let Some(m) = self.manifests.get_mut(&id) else { return };
        m.refcount = m.refcount.saturating_sub(1);
        if m.refcount > 0 {
            return;
        }

        let m = self.manifests.remove(&id).expect("present");
        self.stored_bytes -= m.bytes.len();

        if let Some(ids) = self.by_hash.get_mut(&(m.guid, m.hash)) {
            ids.retain(|x| *x != id);
            if ids.is_empty() {
                self.by_hash.remove(&(m.guid, m.hash));
            }
        }
        if let Some(ids) = self.by_provider.get_mut(&m.guid) {
            ids.retain(|x| *x != id);
            if ids.is_empty() {
                self.by_provider.remove(&m.guid);
            }
        }

        if evicting {
            self.stats.manifests_evicted += 1;
        }
        self.freed.push(id);
    }

    /// Evicts least-recently-used bindings (never `keep`) until all store
    /// limits hold.
    fn enforce_caps(&mut self, keep: (Guid, u32)) {
        while self.by_process.len() > MAX_PROCESS_BINDINGS
            || self.manifests.len() > MAX_DISTINCT_MANIFESTS
            || self.stored_bytes > MAX_STORED_MANIFEST_BYTES {
            let victim = self.by_process
                .iter()
                .filter(|(k, _)| **k != keep)
                .min_by_key(|(_, b)| b.last_used)
                .map(|(k, b)| (*k, b.manifest));

            let Some((key, manifest)) = victim else { break };
            self.by_process.remove(&key);
            self.stats.bindings_evicted += 1;
            self.decref(manifest, true);
            self.warn_once(key.0, || warn!(
                pid = key.1,
                "EventSource manifest store at capacity; evicting least-recently-used process binding"
            ));
        }
    }

    fn warn_once(&mut self, provider: Guid, log: impl FnOnce()) {
        const MAX_WARNED: usize = 1024;
        if self.warned.len() < MAX_WARNED && self.warned.insert(provider) {
            log();
        }
    }

    #[cfg(test)]
    fn binding_count(&self) -> usize {
        self.by_process.len()
    }

    #[cfg(test)]
    fn manifest_count(&self) -> usize {
        self.manifests.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envelope::build_chunk;
    use manifest::{TEST_MANIFEST, TEST_PROVIDER};

    fn install_single_chunk(store: &mut InbandManifestStore, provider: Guid, pid: u32, xml: &str) {
        store.ingest_chunk(provider, pid, 1, &build_chunk(1, 0, xml.as_bytes()), Instant::now());
    }

    fn resolve_id(store: &mut InbandManifestStore, provider: Guid, pid: u32, id: u16, version: u8) -> Option<ManifestId> {
        store.resolve(provider, pid, id, version).map(Resolved::manifest)
    }

    /// A minimal manifest for `TEST_PROVIDER` where event 1 has `field` only.
    fn variant_manifest(field: &str) -> String {
        format!(r#"<events><provider name="OneCollect-Test-InbandManifest" guid="{{369e340b-d54c-5d95-1211-b7a318f16882}}">
<events><event value="1" symbol="AllScalars" template="T"/></events>
<templates><template tid="T"><data name="{field}" inType="win:Int64"/></template></templates>
</provider></events>"#)
    }

    fn field_name(store: &InbandManifestStore, id: ManifestId) -> String {
        store.event(id, 1, 0).unwrap().1.fields[0].name.clone()
    }

    #[test]
    fn descriptor_detection() {
        assert!(is_manifest_descriptor(0xFFFE, 0xFE, 0xFFFE));
        assert!(!is_manifest_descriptor(0xFFFE, 0xFE, 0));
        assert!(!is_manifest_descriptor(0xFFFE, 0, 0xFFFE));
        assert!(!is_manifest_descriptor(1, 0xFE, 0xFFFE));
    }

    #[test]
    fn multi_chunk_install_and_resolve() {
        let mut store = InbandManifestStore::default();
        let bytes = TEST_MANIFEST.as_bytes();
        let (a, b) = bytes.split_at(bytes.len() / 3);
        let (b, c) = b.split_at(b.len() / 2);
        let now = Instant::now();

        store.ingest_chunk(TEST_PROVIDER, 10, 1, &build_chunk(3, 0, a), now);
        store.ingest_chunk(TEST_PROVIDER, 10, 1, &build_chunk(3, 2, c), now);
        assert!(resolve_id(&mut store, TEST_PROVIDER, 10, 1, 0).is_none(), "not complete yet");
        store.ingest_chunk(TEST_PROVIDER, 10, 1, &build_chunk(3, 1, b), now);

        let id = resolve_id(&mut store, TEST_PROVIDER, 10, 1, 0).expect("resolved");
        let (provider_name, def) = store.event(id, 1, 0).unwrap();
        assert_eq!(provider_name, "OneCollect-Test-InbandManifest");
        assert_eq!(def.name, "AllScalars");

        // Undefined (id, version) does not resolve.
        assert!(resolve_id(&mut store, TEST_PROVIDER, 10, 8, 0).is_none());
        assert!(resolve_id(&mut store, TEST_PROVIDER, 10, 8, 2).is_some());

        let stats = store.stats();
        assert_eq!(stats.chunks, 3);
        assert_eq!(stats.manifests_completed, 1);
        assert_eq!(stats.manifests_interned, 1);
        assert!(!store.has_partials());
    }

    #[test]
    fn identical_manifests_share_id_and_resend_is_stable() {
        let mut store = InbandManifestStore::default();
        install_single_chunk(&mut store, TEST_PROVIDER, 1, TEST_MANIFEST);
        install_single_chunk(&mut store, TEST_PROVIDER, 2, TEST_MANIFEST);
        install_single_chunk(&mut store, TEST_PROVIDER, 1, TEST_MANIFEST);

        let a = resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).unwrap();
        let b = resolve_id(&mut store, TEST_PROVIDER, 2, 1, 0).unwrap();
        assert_eq!(a, b);
        assert_eq!(store.stats().manifests_interned, 1);
        assert_eq!(store.manifest_count(), 1);
        assert!(store.take_freed().is_empty());
    }

    #[test]
    fn processes_with_different_manifests_use_their_own() {
        let mut store = InbandManifestStore::default();
        install_single_chunk(&mut store, TEST_PROVIDER, 1, &variant_manifest("old"));
        install_single_chunk(&mut store, TEST_PROVIDER, 2, &variant_manifest("new"));

        let a = resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).unwrap();
        let b = resolve_id(&mut store, TEST_PROVIDER, 2, 1, 0).unwrap();
        assert_ne!(a, b);
        assert_eq!(field_name(&store, a), "old");
        assert_eq!(field_name(&store, b), "new");

        // An unbound process must not guess between conflicting manifests.
        assert!(resolve_id(&mut store, TEST_PROVIDER, 3, 1, 0).is_none());
    }

    #[test]
    fn unbound_process_falls_back_only_when_all_agree() {
        let mut store = InbandManifestStore::default();
        install_single_chunk(&mut store, TEST_PROVIDER, 1, &variant_manifest("same"));
        install_single_chunk(&mut store, TEST_PROVIDER, 2, &variant_manifest("same"));

        let id = resolve_id(&mut store, TEST_PROVIDER, 99, 1, 0).expect("safe fallback");
        assert_eq!(field_name(&store, id), "same");
        assert_eq!(store.resolve(TEST_PROVIDER, 99, 1, 0), Some(Resolved::Fallback(id)));
        assert_eq!(store.resolve(TEST_PROVIDER, 1, 1, 0), Some(Resolved::Bound(id)));

        // Another provider's events are never resolved via this fallback.
        assert!(resolve_id(&mut store, Guid::from_u128(7), 99, 1, 0).is_none());
    }

    #[test]
    fn rebinding_frees_unreferenced_manifest() {
        let mut store = InbandManifestStore::default();
        install_single_chunk(&mut store, TEST_PROVIDER, 1, &variant_manifest("v1"));
        let v1 = resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).unwrap();

        // Same PID (e.g. PID reuse / new build) sends a different manifest.
        install_single_chunk(&mut store, TEST_PROVIDER, 1, &variant_manifest("v2"));
        let v2 = resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).unwrap();

        assert_ne!(v1, v2);
        assert_eq!(field_name(&store, v2), "v2");
        assert_eq!(store.take_freed(), vec![v1]);
        assert!(store.event(v1, 1, 0).is_none());
        assert_eq!(store.manifest_count(), 1);
        assert_eq!(store.stats().manifests_evicted, 0, "rebinding is not an eviction");
    }

    #[test]
    fn hash_collision_is_resolved_by_byte_comparison() {
        let mut store = InbandManifestStore::default();
        store.install_hashed(TEST_PROVIDER, 1, variant_manifest("a").into_bytes(), 42);
        store.install_hashed(TEST_PROVIDER, 2, variant_manifest("b").into_bytes(), 42);

        let a = resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).unwrap();
        let b = resolve_id(&mut store, TEST_PROVIDER, 2, 1, 0).unwrap();
        assert_ne!(a, b, "same hash but different bytes must not be merged");
        assert_eq!(field_name(&store, b), "b");
        assert_eq!(store.stats().manifests_interned, 2);
    }

    #[test]
    fn rejected_manifests_keep_existing_binding() {
        let mut store = InbandManifestStore::default();
        install_single_chunk(&mut store, TEST_PROVIDER, 1, &variant_manifest("good"));
        install_single_chunk(&mut store, TEST_PROVIDER, 1, "<events><provider");
        install_single_chunk(&mut store, TEST_PROVIDER, 1, &variant_manifest("x").replace("369e340b", "469e340b"));

        let id = resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).unwrap();
        assert_eq!(field_name(&store, id), "good");
        assert_eq!(store.stats().xml_errors, 2);
    }

    #[test]
    fn envelope_and_orphan_errors_are_counted() {
        let mut store = InbandManifestStore::default();
        let now = Instant::now();
        store.ingest_chunk(TEST_PROVIDER, 1, 1, &[0u8; 4], now);
        store.ingest_chunk(TEST_PROVIDER, 1, 1, &build_chunk(2, 1, b"x"), now);

        let stats = store.stats();
        assert_eq!(stats.chunks, 2);
        assert_eq!(stats.envelope_errors, 1);
        assert_eq!(stats.orphan_chunks, 1);
        assert!(resolve_id(&mut store, TEST_PROVIDER, 1, 1, 0).is_none());
    }

    #[test]
    fn binding_cap_evicts_least_recently_used() {
        let mut store = InbandManifestStore::default();
        let xml = variant_manifest("shared");
        for pid in 0..MAX_PROCESS_BINDINGS as u32 {
            install_single_chunk(&mut store, TEST_PROVIDER, pid, &xml);
        }
        // Touch pid 0 so pid 1 becomes the LRU binding.
        assert!(resolve_id(&mut store, TEST_PROVIDER, 0, 1, 0).is_some());

        install_single_chunk(&mut store, TEST_PROVIDER, 100_000, &xml);
        assert_eq!(store.binding_count(), MAX_PROCESS_BINDINGS);
        assert_eq!(store.stats().bindings_evicted, 1);
        assert!(store.by_process.contains_key(&(TEST_PROVIDER, 0)));
        assert!(!store.by_process.contains_key(&(TEST_PROVIDER, 1)));
        // The shared manifest is still referenced, so nothing was freed.
        assert!(store.take_freed().is_empty());
    }

    #[test]
    fn distinct_manifest_cap_evicts_and_frees() {
        let mut store = InbandManifestStore::default();
        for pid in 0..=MAX_DISTINCT_MANIFESTS as u32 {
            install_single_chunk(&mut store, TEST_PROVIDER, pid, &variant_manifest(&format!("f{pid}")));
        }

        assert_eq!(store.manifest_count(), MAX_DISTINCT_MANIFESTS);
        assert_eq!(store.stats().manifests_evicted, 1);
        assert_eq!(store.take_freed().len(), 1);
        // The oldest process (pid 0) lost its binding.
        assert!(!store.by_process.contains_key(&(TEST_PROVIDER, 0)));
    }
}
