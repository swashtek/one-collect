// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # TDH-Based Dynamic Event Decoder
//!
//! This module provides [`TdhDecoder`], a runtime schema decoder for
//! TraceLogging, TraceLoggingDynamic, and manifest-based ETW events.  It
//! uses the Windows Trace Data Helper (TDH) APIs to discover event schemas
//! on the fly and converts them into the standard [`EventFormat`] /
//! [`EventData`] representation used throughout one_collect.
//!
//! ## Design
//!
//! The decoder caches the [`EventFormat`] directly.  TraceLogging schemas
//! are keyed by their raw inline schema bytes; OS-registered manifest schemas
//! by their `(Provider GUID, Id, Version)` identity; in-band EventSource
//! schemas by `(ManifestId, Id, Version)`, where `ManifestId` identifies one
//! distinct manifest content.  All keyspaces are split by pointer width and
//! index into one shared arena of decoded schemas (append-only, except that
//! slots of evicted in-band manifests are recycled).  Because the format uses
//! the framework's standard `LocationType`
//! conventions (`StaticString`, `StaticUTF16String`, etc. with `size = 0`
//! for variable-length fields), the cached `EventFormat` is schema-stable:
//! it doesn't depend on any particular event's payload bytes.  A cache hit
//! collapses to a hashmap probe + `EventData::new`, effectively zero
//! per-event overhead.
//!
//! Source selection is transparent and happens per event in
//! [`TdhDecoder::decode`]:
//!
//! 1. An event carrying an inline SCHEMA_TL item takes the **TraceLogging**
//!    path, even when its provider also emitted an in-band manifest (an
//!    `EventSource` may write some events via TraceLogging).
//! 2. Classic (MOF/WBEM) events are rejected as `Unsupported`.
//! 3. An **EventSource in-band manifest chunk** (`Id 0xFFFE`, `Opcode 0xFE`,
//!    `Task 0xFFFE`) is consumed as schema metadata and reported as
//!    [`TdhDecodeError::InbandManifest`]; it never reaches TDH.
//! 4. An event defined by a reassembled **in-band manifest** for its
//!    `(provider, process)` is decoded from that manifest.
//! 5. Anything else takes the **OS-registered manifest** path.
//!
//! TraceLogging and OS-registered manifests share `TdhGetEventInformation`
//! as their schema source, so their byte-level decoding is source-agnostic.
//!
//! Variable-length field resolution (scanning for null terminators, reading
//! length prefixes) is handled lazily by the framework's existing
//! `try_get_field_data_closure` skip-chain machinery in `event/mod.rs`.
//! Only fields the consumer actually reads incur scanning cost.
//!
//! ## Scope
//!
//! - **Supported**: TraceLogging, TraceLoggingDynamic, OS-registered
//!   manifest, and .NET `EventSource` in-band manifest events; nested struct
//!   fields (flattened with dot-notation names), basic scalar and string
//!   property types, EventSource `byte[]` (u32-length-prefixed blobs),
//!   32-bit and 64-bit event payloads.
//!
//! - **Not supported**: classic (MOF/WBEM) and WPP events (fast-rejected /
//!   returned as `Unsupported`).
//!
//! - **Not yet supported** (future work): map / enum value resolution,
//!   array-typed properties, and properties whose length or count is given
//!   by another (non-adjacent) property.
//!
//! ## OS-registered manifests
//!
//! The OS-registered manifest path resolves schemas through
//! `TdhGetEventInformation`, which consults manifests registered with the OS
//! (`HKLM\...\WINEVT\Publishers`, the `wevtutil im` model, e.g.
//! `Microsoft-Windows-Kernel-*`).  The provider's manifest must be registered
//! on the *decoding* machine; if it isn't, `decode()` returns
//! [`TdhDecodeError::NotFound`].  Negative results are not cached, so a
//! manifest registered after the decoder starts is picked up on the next
//! matching event.
//!
//! ## EventSource in-band manifests
//!
//! .NET `EventSource` providers in their default (manifest) mode do not
//! register their manifest with the OS; they emit it in-band as chunked
//! events whenever a session enables them.  The decoder reassembles the
//! chunks per emitting thread, parses the XML, and binds the manifest to the
//! emitting process, so processes running different builds of the same
//! `EventSource` each decode with their own layout (see the `eventsource`
//! module).  Events that arrive before their manifest is complete fall
//! through to the OS-registered path (normally `NotFound`).  Once an in-band
//! manifest is available it takes precedence over an OS-registered manifest
//! for the same provider.  Ingestion problems never fail the stream; they are
//! counted in [`TdhDecoder::inband_manifest_stats`].

use super::abi::{EVENT_RECORD, EventRecordExt};
use super::eventsource::{self, InbandManifestStore, ManifestId, Resolved};
use crate::Guid;
use crate::event::{EventData, EventField, EventFormat, LocationType};

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use std::time::Instant;
use tracing::{debug, trace, warn};
use twox_hash::XxHash64;

// ── windows-sys imports for TDH ─────────────────────────────────────

use windows_sys::Win32::System::Diagnostics::Etw::{
    TRACE_EVENT_INFO,
    EVENT_PROPERTY_INFO,
    TdhGetEventInformation,
    EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,

    // Decoding-source discrimination (TraceLogging vs. manifest/WPP).
    DECODING_SOURCE,
    DecodingSourceTlg,
    DecodingSourceXMLFile,

    TDH_INTYPE_UNICODESTRING,
    TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_INT8,
    TDH_INTYPE_UINT8,
    TDH_INTYPE_INT16,
    TDH_INTYPE_UINT16,
    TDH_INTYPE_INT32,
    TDH_INTYPE_UINT32,
    TDH_INTYPE_INT64,
    TDH_INTYPE_UINT64,
    TDH_INTYPE_FLOAT,
    TDH_INTYPE_DOUBLE,
    TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_BINARY,
    TDH_INTYPE_GUID,
    TDH_INTYPE_POINTER,
    TDH_INTYPE_FILETIME,
    TDH_INTYPE_SYSTEMTIME,
    TDH_INTYPE_SID,
    TDH_INTYPE_HEXINT32,
    TDH_INTYPE_HEXINT64,
    // Manifest-range counted strings (mc.exe emits these for
    // `CountedUnicodeString` / `CountedAnsiString`, since 2018).
    TDH_INTYPE_MANIFEST_COUNTEDSTRING,
    TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
    // WBEM/WMI-range counted strings (same on-wire format, different
    // numeric constant).
    TDH_INTYPE_COUNTEDSTRING,
    TDH_INTYPE_COUNTEDANSISTRING,
    TDH_INTYPE_REVERSEDCOUNTEDSTRING,
    TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,
    TDH_INTYPE_NONNULLTERMINATEDSTRING,
    TDH_INTYPE_NONNULLTERMINATEDANSISTRING,

    // PROPERTY_FLAGS enum values used in EVENT_PROPERTY_INFO::Flags.
    PropertyStruct,
    PropertyParamLength,
    PropertyParamCount,
};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND};

/// `EVENT_HEADER_FLAG_32_BIT_HEADER` from the Windows SDK.
const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x0020;

/// `EVENT_HEADER_FLAG_CLASSIC_HEADER` from the Windows SDK.
///
/// Set for classic (MOF/WBEM) events, whose identity is an event-class
/// GUID + Opcode rather than the `(Provider, Id, Version)` tuple used for
/// manifest events.  Such events must never take the manifest path: their
/// `EVENT_DESCRIPTOR.Id` is commonly `0`, so multiple distinct classic
/// events from one provider would collapse onto the same `ManifestEventKey`.
const EVENT_HEADER_FLAG_CLASSIC_HEADER: u16 = 0x0100;

// Aliases for PROPERTY_FLAGS constants (i32 in windows-sys) to keep
// call-site flag checks concise.
const PROPERTY_STRUCT: i32       = PropertyStruct;
const PROPERTY_PARAM_LENGTH: i32 = PropertyParamLength;
const PROPERTY_PARAM_COUNT: i32  = PropertyParamCount;

// EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL is imported from windows-sys
// (u32 = 11).  Usage sites cast to u16 where the ExtType field requires it.

// ── Error type ──────────────────────────────────────────────────────

/// Errors that can occur during TDH-based schema decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum TdhDecodeError {
    /// No decodable schema was found for the event.
    ///
    /// For TraceLogging this means no inline
    /// `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended-data item was
    /// present.  For manifest events this also covers "manifest not
    /// registered on this machine" (`TdhGetEventInformation` returns
    /// `ERROR_NOT_FOUND`), including EventSource events that arrive before
    /// their in-band manifest has been fully received.
    NotFound,
    /// The event's schema source is recognised but not supported by this
    /// decoder (e.g. classic (MOF/WBEM) events, which are fast-rejected
    /// before the manifest path, or WPP and WBEM decoding sources reached
    /// via the manifest dispatch path).
    Unsupported,
    /// A Win32 error code was returned by `TdhGetEventInformation`.
    Win32(u32),
    /// The `TRACE_EVENT_INFO` returned by TDH is structurally invalid.
    Malformed(&'static str),
    /// The event is an EventSource in-band manifest chunk (`Id 0xFFFE`,
    /// `Opcode 0xFE`, `Task 0xFFFE`).  It was consumed as schema metadata
    /// and has no payload to decode.
    ///
    /// Returned for **every** such event, whether or not the chunk was
    /// accepted, so consumers can drop all manifest metadata with one rule.
    /// Ingestion problems are reported via
    /// [`TdhDecoder::inband_manifest_stats`].  Diagnostic consumers still
    /// hold the raw `EVENT_RECORD` and may forward it.
    InbandManifest,
}

impl std::fmt::Display for TdhDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no decodable schema found for event"),
            Self::Unsupported => write!(f, "event schema source is not supported"),
            Self::Win32(code) => write!(f, "TdhGetEventInformation failed with Win32 error {code}"),
            Self::Malformed(msg) => write!(f, "malformed TRACE_EVENT_INFO: {msg}"),
            Self::InbandManifest => write!(f, "EventSource in-band manifest event (schema metadata, no payload)"),
        }
    }
}

impl std::error::Error for TdhDecodeError {}

// ── Public metadata types ───────────────────────────────────────────

/// Which schema source decoded an event.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SchemaSourceKind {
    /// Inline TraceLogging / TraceLoggingDynamic schema (SCHEMA_TL).
    TraceLogging,
    /// Manifest registered with the OS, resolved via `TdhGetEventInformation`.
    RegisteredManifest,
    /// .NET `EventSource` manifest received in-band in the event stream.
    InbandManifest,
}

/// Cumulative counters for EventSource in-band manifest ingestion.
///
/// Obtained from [`TdhDecoder::inband_manifest_stats`].  All counters only
/// ever increase, so consumers can publish deltas between snapshots.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InbandManifestStats {
    /// Manifest chunk events seen (accepted or not).
    pub chunks: u64,
    /// Manifests fully reassembled from chunks.
    pub manifests_completed: u64,
    /// Distinct manifest contents parsed and stored (identical re-sends are
    /// not re-parsed and do not count).
    pub manifests_interned: u64,
    /// Chunks with an invalid envelope (bad magic, format, version, range).
    pub envelope_errors: u64,
    /// Reassembled manifests rejected as malformed XML, non-UTF-8, over a
    /// limit, or not matching the emitting provider GUID.
    pub xml_errors: u64,
    /// Non-zero chunks discarded because their emission's chunk 0 was not
    /// seen (e.g. lost, or collection started mid-emission).
    pub orphan_chunks: u64,
    /// Partial manifests abandoned (restarted, duplicate or mismatched chunk,
    /// too large, expired, or evicted).
    pub partials_dropped: u64,
    /// `(provider, process)` bindings evicted because the store was full.
    pub bindings_evicted: u64,
    /// Stored manifests freed because the store was full.
    pub manifests_evicted: u64,
}

impl InbandManifestStats {
    /// Sum of the counters that indicate a manifest was (partially) lost:
    /// envelope errors, rejected manifests, orphan chunks and dropped partials.
    pub fn ingest_errors(&self) -> u64 {
        self.envelope_errors + self.xml_errors + self.orphan_chunks + self.partials_dropped
    }
}

// ── Cached schema ───────────────────────────────────────────────────

/// Cached schema: the event name and the `EventFormat` that the
/// framework's `try_get_field_data_closure` can resolve lazily.
#[derive(Clone)]
struct CachedSchema {
    /// The event name (TraceLogging event name, manifest task name, or
    /// EventSource event `symbol`).
    event_name: String,
    /// Schema-stable `EventFormat`: field offsets are absolute for
    /// fixed-size fields, and the framework's skip chain handles
    /// variable-length fields lazily via `size = 0`.
    format: EventFormat,
    /// Monotonic ID assigned at insertion time.
    schema_id: SchemaId,
    /// Provider name from the schema source, when known.
    provider_name: Option<String>,
    /// Which schema source produced this schema.
    source: SchemaSourceKind,
}

/// Hash builder using XxHash64, matching the rest of the ETW module.
type XxBuildHasher = BuildHasherDefault<XxHash64>;

/// Identity of a manifest-based event's schema.
///
/// Manifest events do not carry their layout inline; instead the OS holds a
/// registered manifest that pins the `(Provider GUID, Id, Version)` tuple to
/// a fixed layout.  That tuple is therefore the natural cache key, mirroring
/// how TraceLogging keys on its inline schema bytes.
///
/// Note: the derived `Hash` delegates to [`Guid`]'s `Hash` impl, which hashes
/// only the first three GUID fields (`data1`/`data2`/`data3`), not the
/// trailing `data4` bytes.  Equality is still full (derived `Eq` compares all
/// fields), so correctness is unaffected, but two provider GUIDs differing
/// only in their last 8 bytes share a hash bucket.  Provider GUIDs vary in
/// their leading fields in practice, so this is benign; it is called out here
/// so a future change to `Guid`'s `Hash` isn't made without weighing this key.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct ManifestEventKey {
    /// Provider GUID from `EVENT_HEADER.ProviderId`.
    provider: Guid,
    /// Event ID from `EVENT_DESCRIPTOR.Id`.
    id: u16,
    /// Manifest version from `EVENT_DESCRIPTOR.Version`.  A layout change
    /// bumps this, yielding a distinct key.
    version: u8,
}

/// Identity of an in-band EventSource event's schema.
///
/// `manifest` identifies one distinct manifest *content* (see the
/// `eventsource` module), so processes sending identical manifests share
/// cache entries, while differing builds of the same provider never alias.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct InbandEventKey {
    manifest: ManifestId,
    id: u16,
    version: u8,
}

/// Schema cache: one `Vec` arena of decoded schemas shared by all schema
/// sources, indexed by per-source, per-pointer-width maps.
///
/// TraceLogging is keyed by its raw inline schema bytes; OS-registered
/// manifest events by their `(Provider, Id, Version)` [`ManifestEventKey`];
/// in-band EventSource events by [`InbandEventKey`].  The sources use
/// different key *types*, so they need separate maps (a `HashMap` is
/// monomorphic in its key), but the decoded [`CachedSchema`] is source-
/// agnostic, so storage stays unified in one arena.
///
/// TraceLogging and OS-manifest slots are never removed, so their indices
/// stay valid for the life of the cache.  In-band slots are released when
/// their manifest is evicted from the in-band store ([`Self::remove_inband`])
/// and recycled through `free`; their map entries are removed at the same
/// time, so no live map entry ever points at a recycled slot.
///
/// Storing a `Copy` index (rather than the schema inline in the map) lets the
/// hot path hash the key exactly once: the index is copied out, ending the
/// map borrow, and the schema is then read from `schemas`.
struct SchemaCache {
    /// Decoded schemas, indexed by the maps below.  `None` only for recycled
    /// in-band slots awaiting reuse.
    schemas: Vec<Option<CachedSchema>>,
    /// Indices of released (`None`) slots available for reuse.
    free: Vec<usize>,
    /// TraceLogging schema bytes → arena index (64-bit / 32-bit payloads).
    tl_64: HashMap<Vec<u8>, usize, XxBuildHasher>,
    tl_32: HashMap<Vec<u8>, usize, XxBuildHasher>,
    /// Manifest `(Provider, Id, Version)` → arena index (64/32-bit payloads).
    manifest_64: HashMap<ManifestEventKey, usize, XxBuildHasher>,
    manifest_32: HashMap<ManifestEventKey, usize, XxBuildHasher>,
    /// In-band `(ManifestId, Id, Version)` → arena index (64/32-bit payloads).
    inband_64: HashMap<InbandEventKey, usize, XxBuildHasher>,
    inband_32: HashMap<InbandEventKey, usize, XxBuildHasher>,
    /// Manifest keys whose decoding source is permanently unsupported
    /// (WPP / WBEM reached via the manifest dispatch path).  Caching these
    /// avoids a `TdhGetEventInformation` round trip on every subsequent event
    /// from a chatty unsupported provider.  Pointer-width independent: the
    /// decoding source is a property of the provider's registration, not the
    /// payload width.  Only *permanent* negatives live here; `NotFound` is
    /// never cached, since a manifest can register after the decoder starts.
    manifest_unsupported: HashSet<ManifestEventKey, XxBuildHasher>,
}

impl SchemaCache {
    fn new() -> Self {
        Self {
            schemas: Vec::new(),
            free: Vec::new(),
            tl_64: HashMap::with_hasher(XxBuildHasher::default()),
            tl_32: HashMap::with_hasher(XxBuildHasher::default()),
            manifest_64: HashMap::with_hasher(XxBuildHasher::default()),
            manifest_32: HashMap::with_hasher(XxBuildHasher::default()),
            inband_64: HashMap::with_hasher(XxBuildHasher::default()),
            inband_32: HashMap::with_hasher(XxBuildHasher::default()),
            manifest_unsupported: HashSet::with_hasher(XxBuildHasher::default()),
        }
    }

    /// Releases every cached schema built from in-band manifest `manifest`
    /// (both pointer widths), making their slots available for reuse.
    fn remove_inband(&mut self, manifest: ManifestId) {
        for map in [&mut self.inband_64, &mut self.inband_32] {
            map.retain(|key, idx| {
                if key.manifest != manifest {
                    return true;
                }
                self.schemas[*idx] = None;
                self.free.push(*idx);
                false
            });
        }
    }

    /// Returns the index of a cached schema, or `None` on a miss.
    ///
    /// The source match is kept inside the cache so callers do not need to
    /// select a source-specific map.  Manifest negative-cache policy stays
    /// separate because TraceLogging has no equivalent permanent-negative
    /// state.
    fn index_of(
        &self,
        source: &SchemaSource<'_>,
        is_32bit: bool,
    ) -> Option<usize> {
        match source {
            SchemaSource::TraceLogging(key) => {
                let map = if is_32bit { &self.tl_32 } else { &self.tl_64 };
                map.get(*key).copied()
            }
            SchemaSource::Manifest(key) => {
                let map = if is_32bit { &self.manifest_32 } else { &self.manifest_64 };
                map.get(key).copied()
            }
            SchemaSource::Inband(key) => {
                let map = if is_32bit { &self.inband_32 } else { &self.inband_64 };
                map.get(key).copied()
            }
        }
    }

    /// Returns `true` if `key` has been recorded as permanently unsupported.
    fn is_manifest_unsupported(&self, key: &ManifestEventKey) -> bool {
        self.manifest_unsupported.contains(key)
    }

    /// Records `key` as permanently unsupported (WPP / WBEM decoding source).
    fn mark_manifest_unsupported(&mut self, key: ManifestEventKey) {
        self.manifest_unsupported.insert(key);
    }

    /// Maps a schema source to a schema index and returns it.  Intended for
    /// the cache miss path, where the source is not yet present.
    ///
    /// The schema is only stored when the key is actually vacant, so a
    /// (contract-violating) duplicate key returns the existing index without
    /// orphaning a freshly built schema.  The key is hashed once via a single
    /// `entry` lookup.  A vacant key takes a recycled slot if one is free.
    fn insert(
        &mut self,
        source: SchemaSource<'_>,
        is_32bit: bool,
        schema: CachedSchema,
    ) -> usize {
        use std::collections::hash_map::Entry;

        // Picks a slot only once the key is known to be vacant.
        fn store(
            schemas: &mut Vec<Option<CachedSchema>>,
            free: &mut Vec<usize>,
            schema: CachedSchema,
        ) -> usize {
            match free.pop() {
                Some(idx) => {
                    schemas[idx] = Some(schema);
                    idx
                }
                None => {
                    schemas.push(Some(schema));
                    schemas.len() - 1
                }
            }
        }

        let schemas = &mut self.schemas;
        let free = &mut self.free;
        match source {
            SchemaSource::TraceLogging(key) => {
                let map = if is_32bit { &mut self.tl_32 } else { &mut self.tl_64 };
                match map.entry(key.to_vec()) {
                    // Already present: return the existing index and drop `schema`.
                    Entry::Occupied(e) => *e.get(),
                    Entry::Vacant(e) => *e.insert(store(schemas, free, schema)),
                }
            }
            SchemaSource::Manifest(key) => {
                let map = if is_32bit { &mut self.manifest_32 } else { &mut self.manifest_64 };
                match map.entry(key) {
                    Entry::Occupied(e) => *e.get(),
                    Entry::Vacant(e) => *e.insert(store(schemas, free, schema)),
                }
            }
            SchemaSource::Inband(key) => {
                let map = if is_32bit { &mut self.inband_32 } else { &mut self.inband_64 };
                match map.entry(key) {
                    Entry::Occupied(e) => *e.get(),
                    Entry::Vacant(e) => *e.insert(store(schemas, free, schema)),
                }
            }
        }
    }

    /// Reads a cached schema by its index.
    ///
    /// `idx` always comes from an `index_of` or `insert` call.  Slots are
    /// only released together with every map entry that points at them
    /// ([`Self::remove_inband`]), so a live index never dangles.
    fn get(&self, idx: usize) -> &CachedSchema {
        self.schemas[idx].as_ref().expect("cache index refers to a live schema slot")
    }
}

// ── TdhDecoder ──────────────────────────────────────────────────────

/// Result of a successful [`TdhDecoder::decode`] call.
///
/// Contains the decoded [`EventData`], the resolved `event_name`,
/// and a monotonic [`SchemaId`] that exporters can use as a cheap
/// lookup key for format registration.
#[non_exhaustive]
pub struct TdhDecodedEvent<'a> {
    /// The decoded event data.
    pub event_data: EventData<'a>,
    /// The resolved event name, or `None` if the schema has no name.
    ///
    /// For TraceLogging this is the event name (the primary identity, as
    /// the event ID is often 0); for OS-registered manifest events it is the
    /// task name; for EventSource in-band manifest events it is the event's
    /// `symbol` (the EventSource method name, e.g. `RequestStart`), falling
    /// back to the task name.  Consumers can use this for OTEL log record
    /// naming without a second cache probe.
    ///
    /// Note: for OS-registered manifest events this is the Task name, which
    /// is not unique per event (multiple events can share a Task, e.g.
    /// Start/Stop/Info under one Task all report the same name).
    /// Identity-sensitive consumers (dedup, routing, record identity) should
    /// use `schema_id` (or the event's `Id`/`Opcode`) rather than treating
    /// the name as unique.
    pub event_name: Option<&'a str>,
    /// Monotonic identifier for this event's schema.
    ///
    /// Each distinct schema (identified by its inline TraceLogging bytes, its
    /// OS manifest `(Provider, Id, Version)` tuple, or its in-band manifest
    /// content and `(Id, Version)`, split by pointer width) gets a unique
    /// `SchemaId` on first insertion into the cache.  The same ID is returned
    /// on every subsequent cache hit.  Exporters can use this as a cheap
    /// lookup key to avoid re-registering the `EventFormat`:
    ///
    /// ```ignore
    /// let event = decoder.decode(record)?;
    /// let id = *my_map.entry(event.schema_id)
    ///     .or_insert_with(|| exporter.register(event.event_data.format()));
    /// ```
    pub schema_id: SchemaId,
    /// The provider name from the schema source, when known.
    ///
    /// `Some` for EventSource in-band manifest events (the manifest's
    /// `<provider name>`); currently `None` for TraceLogging and
    /// OS-registered manifest events.
    pub provider_name: Option<&'a str>,
    /// Which schema source decoded this event.
    pub source: SchemaSourceKind,
}

/// Opaque monotonic identifier for a cached TDH schema.
///
/// Assigned once on cache insertion and returned with every decoded event
/// that matches the same schema.  Suitable as a `HashMap` key for
/// exporter-side format registration.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchemaId(u64);

/// The schema source of an event, paired with the cache key used to look it
/// up and (on a miss) insert it.
///
/// Classifying the source up front lets [`TdhDecoder::decode`] own the entire
/// cache interaction — lookup, miss dispatch, and insert — in one place, so
/// the `decode_*` helpers are reached only when a *real* decode is required.
enum SchemaSource<'a> {
    /// Inline TraceLogging schema, keyed by its raw schema bytes.
    TraceLogging(&'a [u8]),
    /// Manifest event, keyed by its `(Provider, Id, Version)` identity.
    Manifest(ManifestEventKey),
    /// EventSource in-band manifest event, keyed by manifest content + `(Id, Version)`.
    Inband(InbandEventKey),
}

/// How many `decode()` calls pass between amortized sweeps of expired
/// partial in-band manifests.
const INBAND_SWEEP_INTERVAL: u64 = 4096;

/// Runtime decoder for TraceLogging, TraceLoggingDynamic, OS-registered
/// manifest, and .NET `EventSource` in-band manifest ETW events.
///
/// Caches the `EventFormat` directly per schema.  Cache hits are a
/// hashmap probe + `EventData::new` with no per-event allocation.
pub struct TdhDecoder {
    cache: SchemaCache,
    /// Reusable aligned buffer for `TdhGetEventInformation` results.
    tei_buf: AlignedTeiBuf,
    /// Monotonic counter for assigning unique `SchemaId`s.
    next_schema_id: u64,
    /// EventSource in-band manifest assembly and storage.
    inband: InbandManifestStore,
    /// OS-manifest keys confirmed `NotFound` while an agreed fallback
    /// in-band manifest exists (see [`Resolved::Fallback`]).  Lets later
    /// events use the fallback without a `TdhGetEventInformation` call.
    os_manifest_absent: HashSet<ManifestEventKey, XxBuildHasher>,
    /// `decode()` call counter driving the amortized partial-manifest sweep.
    decode_calls: u64,
}

/// Bound on [`TdhDecoder::os_manifest_absent`]; the set is cleared when full.
const MAX_OS_MANIFEST_ABSENT: usize = 65536;

impl TdhDecoder {
    /// Creates a new decoder with an empty schema cache.
    pub fn new() -> Self {
        Self {
            cache: SchemaCache::new(),
            tei_buf: AlignedTeiBuf::new(),
            next_schema_id: 0,
            inband: InbandManifestStore::default(),
            os_manifest_absent: HashSet::with_hasher(XxBuildHasher::default()),
            decode_calls: 0,
        }
    }

    /// Returns cumulative EventSource in-band manifest ingestion counters.
    pub fn inband_manifest_stats(&self) -> InbandManifestStats {
        self.inband.stats()
    }

    /// Decodes an `EVENT_RECORD` into a [`TdhDecodedEvent`].
    ///
    /// The schema source is selected per event (see the module docs):
    /// an inline `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` item selects the
    /// TraceLogging path; an EventSource manifest-chunk event is consumed and
    /// reported as [`TdhDecodeError::InbandManifest`]; an event defined by an
    /// in-band EventSource manifest for its `(provider, process)` is decoded
    /// from that manifest; anything else is resolved as an OS-registered
    /// manifest event through its `(Provider, Id, Version)` identity.
    ///
    /// All cache interaction is centralized here: the source is classified,
    /// the cache is probed, and only on a miss is a `decode_*` helper called
    /// to perform a real decode.  The freshly built schema is then assigned a
    /// `SchemaId` and inserted — so the helpers never touch the positive
    /// cache themselves.
    ///
    /// The returned [`TdhDecodedEvent`] contains the decoded
    /// [`EventData`], the resolved `event_name`, and a monotonic
    /// [`SchemaId`] that exporters can use as a cheap lookup key for
    /// format registration.
    pub fn decode<'a>(
        &'a mut self,
        record: &'a EVENT_RECORD,
    ) -> Result<TdhDecodedEvent<'a>, TdhDecodeError> {
        let is_32bit = (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;

        self.decode_calls = self.decode_calls.wrapping_add(1);
        if self.decode_calls.is_multiple_of(INBAND_SWEEP_INTERVAL) && self.inband.has_partials() {
            self.inband.sweep(Instant::now());
        }

        // Classify the schema source and compute its cache key.  The source
        // borrows only `record`, never `self`, so the mutable `self` borrows
        // below are unconstrained.
        //
        // Classic (MOF/WBEM) events are rejected here rather than in the
        // manifest path: their identity is a class GUID + Opcode, not the
        // `(Provider, Id, Version)` tuple (their `Id` is commonly `0`, so
        // multiple such events would collapse onto one key), so they can never
        // form a valid `ManifestEventKey`.
        //
        // `fallback` is set when the only in-band manifest available is one
        // the emitting process did not send itself.  Any process can emit
        // manifest chunks under any provider GUID, so such a manifest is used
        // only once the OS lookup confirms no registered manifest exists.
        let (source, fallback) = match find_schema_tl(record) {
            // SCHEMA_TL wins even for providers with an in-band manifest: an
            // EventSource may write some events via TraceLogging.
            Some(schema_tl_bytes) => (SchemaSource::TraceLogging(schema_tl_bytes), None),
            None => {
                if (record.EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 {
                    return Err(TdhDecodeError::Unsupported);
                }
                let desc = &record.EventHeader.EventDescriptor;
                let provider = record.provider_guid();

                if eventsource::is_manifest_descriptor(desc.Id, desc.Opcode, desc.Task) {
                    self.ingest_manifest_chunk(record, provider);
                    return Err(TdhDecodeError::InbandManifest);
                }

                let os_key = ManifestEventKey { provider, id: desc.Id, version: desc.Version };
                let inband_key = |manifest| InbandEventKey { manifest, id: desc.Id, version: desc.Version };

                let pid = record.EventHeader.ProcessId;
                match self.inband.resolve(provider, pid, desc.Id, desc.Version) {
                    Some(Resolved::Bound(m)) => (SchemaSource::Inband(inband_key(m)), None),
                    Some(Resolved::Fallback(m)) if self.os_manifest_absent.contains(&os_key) => {
                        (SchemaSource::Inband(inband_key(m)), None)
                    }
                    Some(Resolved::Fallback(m)) => {
                        (SchemaSource::Manifest(os_key), Some((os_key, inband_key(m))))
                    }
                    None => (SchemaSource::Manifest(os_key), None),
                }
            }
        };

        let idx = match self.cached_or_decode(source, record, is_32bit) {
            Ok(idx) => idx,
            Err(TdhDecodeError::NotFound) if fallback.is_some() => {
                let (os_key, inband_key) = fallback.expect("checked by guard");
                // Remember the OS miss so later events skip the TDH round
                // trip and go straight to the agreed in-band manifest.
                if self.os_manifest_absent.len() >= MAX_OS_MANIFEST_ABSENT {
                    self.os_manifest_absent.clear();
                }
                self.os_manifest_absent.insert(os_key);
                self.cached_or_decode(SchemaSource::Inband(inband_key), record, is_32bit)?
            }
            Err(e) => return Err(e),
        };

        let schema = self.cache.get(idx);

        let user_data = record.user_data_slice();
        debug!(
            user_data_len = user_data.len(),
            field_count = schema.format.fields().len(),
            "TDH decode — user_data"
        );
        let event_name = if schema.event_name.is_empty() {
            None
        } else {
            Some(schema.event_name.as_str())
        };

        Ok(TdhDecodedEvent {
            event_data: EventData::new(user_data, user_data, &schema.format),
            event_name,
            schema_id: schema.schema_id,
            provider_name: schema.provider_name.as_deref(),
            source: schema.source,
        })
    }

    /// Returns the cache index for `source`, performing a real decode and
    /// inserting the schema on a miss.
    ///
    /// Centralized caching: a hit reuses the arena slot; a miss assigns a
    /// `SchemaId` and inserts under the key.  Returning the `Copy` index ends
    /// every `self` borrow before the caller reads the schema.
    fn cached_or_decode(
        &mut self,
        source: SchemaSource<'_>,
        record: &EVENT_RECORD,
        is_32bit: bool,
    ) -> Result<usize, TdhDecodeError> {
        if let Some(idx) = self.cache.index_of(&source, is_32bit) {
            return Ok(idx);
        }

        if let SchemaSource::Manifest(key) = &source {
            if self.cache.is_manifest_unsupported(key) {
                return Err(TdhDecodeError::Unsupported);
            }
        }

        let mut schema = match &source {
            SchemaSource::TraceLogging(_) => self.decode_tracelogging(record, is_32bit)?,
            SchemaSource::Manifest(key) => self.decode_manifest(record, is_32bit, key)?,
            SchemaSource::Inband(key) => self.decode_inband(key, is_32bit)?,
        };
        schema.schema_id = SchemaId(self.assign_schema_id());
        Ok(self.cache.insert(source, is_32bit, schema))
    }

    /// Feeds an EventSource manifest chunk to the in-band store and purges
    /// cached schemas of any manifests the store freed as a result.
    fn ingest_manifest_chunk(&mut self, record: &EVENT_RECORD, provider: Guid) {
        self.inband.ingest_chunk(
            provider,
            record.EventHeader.ProcessId,
            record.EventHeader.ThreadId,
            record.user_data_slice(),
            Instant::now(),
        );

        let freed = self.inband.take_freed();
        if !freed.is_empty() {
            // Fallback decisions may refer to freed manifests; re-confirm.
            self.os_manifest_absent.clear();
        }
        for manifest in freed {
            self.cache.remove_inband(manifest);
        }
    }

    /// Builds the schema for an in-band EventSource event after a cache miss.
    fn decode_inband(
        &self,
        key: &InbandEventKey,
        is_32bit: bool,
    ) -> Result<CachedSchema, TdhDecodeError> {
        // `resolve()` only returns manifests that define (id, version), and
        // nothing is freed between resolve and here, so this cannot miss.
        let (provider_name, def) = self.inband
            .event(key.manifest, key.id, key.version)
            .ok_or(TdhDecodeError::NotFound)?;

        let schema = CachedSchema {
            event_name: def.name.clone(),
            format: eventsource::manifest::build_format(&def.fields, is_32bit),
            schema_id: SchemaId(0), // assigned by caller
            provider_name: Some(provider_name.to_string()),
            source: SchemaSourceKind::InbandManifest,
        };
        debug!(
            event_name = %schema.event_name,
            id = key.id,
            version = key.version,
            manifest = key.manifest,
            field_count = schema.format.fields().len(),
            is_32bit,
            "TDH schema cache miss — built EventSource in-band schema"
        );
        Ok(schema)
    }

    /// Performs a real TraceLogging decode after a cache miss, returning the
    /// freshly built (but not yet cached) schema.
    ///
    /// The caller assigns the `SchemaId` and inserts the schema; this helper
    /// only walks the event via `TdhGetEventInformation`.
    fn decode_tracelogging(
        &mut self,
        record: &EVENT_RECORD,
        is_32bit: bool,
    ) -> Result<CachedSchema, TdhDecodeError> {
        call_tdh_get_event_information(record, &mut self.tei_buf)?;
        let schema = build_cached_schema(self.tei_buf.as_bytes(), is_32bit)?;
        debug!(
            event_name = %schema.event_name,
            field_count = schema.format.fields().len(),
            is_32bit,
            "TDH schema cache miss — decoded new TraceLogging schema"
        );
        Ok(schema)
    }

    /// Performs a real manifest decode after a cache miss, returning the
    /// freshly built (but not yet cached) schema.
    ///
    /// The caller assigns the `SchemaId` and inserts the schema; this helper
    /// only walks the event via `TdhGetEventInformation` and enforces the
    /// decoding-source guard:
    ///
    /// After `TdhGetEventInformation`, only a `DecodingSourceXMLFile` result
    /// is a genuine XML manifest.  WPP and WBEM results are returned as
    /// [`TdhDecodeError::Unsupported`] and the key is recorded in the negative
    /// cache, so a chatty unsupported provider pays the round trip only once.
    /// `NotFound` (unregistered manifest) is *not* negatively cached, since it
    /// can flip once a manifest registers.
    fn decode_manifest(
        &mut self,
        record: &EVENT_RECORD,
        is_32bit: bool,
        key: &ManifestEventKey,
    ) -> Result<CachedSchema, TdhDecodeError> {
        call_tdh_get_event_information(record, &mut self.tei_buf)?;

        // Only genuine XML-manifest schemas are cached here.  A "not
        // TraceLogging" event can still be WPP/WBEM, whose identity semantics
        // differ from `ManifestEventKey`; those are unsupported.
        let decoding_source = read_decoding_source(self.tei_buf.as_bytes())?;
        if decoding_source != DecodingSourceXMLFile {
            debug!(decoding_source, "TDH manifest path — unsupported decoding source");
            self.cache.mark_manifest_unsupported(*key);
            return Err(TdhDecodeError::Unsupported);
        }

        let schema = build_cached_schema(self.tei_buf.as_bytes(), is_32bit)?;
        debug!(
            event_name = %schema.event_name,
            id = key.id,
            version = key.version,
            field_count = schema.format.fields().len(),
            is_32bit,
            "TDH schema cache miss — decoded new manifest schema"
        );
        Ok(schema)
    }

    /// Allocates the next monotonic `SchemaId` value.
    fn assign_schema_id(&mut self) -> u64 {
        let id = self.next_schema_id;
        self.next_schema_id = id.wrapping_add(1);
        id
    }
}

impl Default for TdhDecoder {
    fn default() -> Self { Self::new() }
}

// ── Schema extraction from TDH ──────────────────────────────────────

/// Builds a `CachedSchema` from a `TRACE_EVENT_INFO` buffer.
///
/// Emits `EventField`s using the framework's standard `LocationType`
/// conventions so the resulting `EventFormat` is schema-stable and
/// can be cached directly.
fn build_cached_schema(tei_buf: &[u8], is_32bit: bool) -> Result<CachedSchema, TdhDecodeError> {
    if tei_buf.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return Err(TdhDecodeError::Malformed("buffer smaller than TRACE_EVENT_INFO"));
    }

    let tei = unsafe { &*(tei_buf.as_ptr() as *const TRACE_EVENT_INFO) };
    let property_count = tei.PropertyCount as usize;
    let top_level_count = tei.TopLevelPropertyCount as usize;

    let event_name = read_event_name(tei_buf, tei);
    let source = if tei.DecodingSource == DecodingSourceTlg {
        SchemaSourceKind::TraceLogging
    } else {
        SchemaSourceKind::RegisteredManifest
    };

    if property_count == 0 {
        return Ok(CachedSchema {
            event_name,
            format: EventFormat::new(),
            schema_id: SchemaId(0), // assigned by caller
            provider_name: None,
            source,
        });
    }

    let props_offset = std::mem::size_of::<TRACE_EVENT_INFO>()
        - std::mem::size_of::<EVENT_PROPERTY_INFO>();
    let props_size = property_count
        .checked_mul(std::mem::size_of::<EVENT_PROPERTY_INFO>())
        .ok_or(TdhDecodeError::Malformed("property count overflow"))?;
    let props_end = props_offset
        .checked_add(props_size)
        .ok_or(TdhDecodeError::Malformed("property array end overflow"))?;
    if tei_buf.len() < props_end {
        return Err(TdhDecodeError::Malformed("buffer too small for declared property count"));
    }

    let properties: &[EVENT_PROPERTY_INFO] = unsafe {
        std::slice::from_raw_parts(
            tei_buf.as_ptr().add(props_offset) as *const EVENT_PROPERTY_INFO,
            property_count,
        )
    };

    let mut format = EventFormat::new();
    let mut running_offset: usize = 0;
    // Once we encounter the first variable-length field, all subsequent
    // offsets become 0 (the framework's skip chain resolves them lazily).
    let mut seen_variable = false;

    walk_properties(
        tei_buf, properties, 0..top_level_count,
        "", &mut format, &mut running_offset, &mut seen_variable, is_32bit, 0,
    )?;

    Ok(CachedSchema {
        event_name,
        format,
        schema_id: SchemaId(0), // assigned by caller
        provider_name: None,
        source,
    })
}

/// Maximum nesting depth for struct properties.
const MAX_STRUCT_DEPTH: usize = 8;

/// Recursively walks TDH properties, flattening structs, and emits
/// `EventField`s directly into the `EventFormat` using the framework's
/// `LocationType` conventions.
fn walk_properties(
    tei_buf: &[u8],
    properties: &[EVENT_PROPERTY_INFO],
    range: std::ops::Range<usize>,
    prefix: &str,
    format: &mut EventFormat,
    running_offset: &mut usize,
    seen_variable: &mut bool,
    is_32bit: bool,
    depth: usize,
) -> Result<(), TdhDecodeError> {
    for i in range {
        if i >= properties.len() {
            return Err(TdhDecodeError::Malformed("property index out of bounds"));
        }

        let prop = &properties[i];
        let raw_name = read_property_name(tei_buf, prop);
        let name = if raw_name.is_empty() { std::format!("field{i}") } else { raw_name };
        let qualified_name = if prefix.is_empty() {
            name
        } else {
            std::format!("{prefix}.{name}")
        };

        let flags = prop.Flags;

        // ── Struct property ─────────────────────────────────────────
        if (flags & PROPERTY_STRUCT) != 0 {
            if depth >= MAX_STRUCT_DEPTH {
                return Err(TdhDecodeError::Malformed("struct nesting depth exceeded"));
            }
            let struct_info = unsafe { prop.Anonymous1.structType };
            let start = struct_info.StructStartIndex as usize;
            let count = struct_info.NumOfStructMembers as usize;
            walk_properties(
                tei_buf, properties, start..start + count,
                &qualified_name, format, running_offset, seen_variable, is_32bit, depth + 1,
            )?;
            continue;
        }

        // ── Array/param-count properties ─────────────────────────────
        if (flags & PROPERTY_PARAM_COUNT) != 0 {
            let count = unsafe { prop.Anonymous2.count } as usize;
            if count != 1 {
                debug!(field = %qualified_name, count, "skipping unsupported array property");
                let offset = if *seen_variable { 0 } else { *running_offset };
                format.add_field(EventField::new(
                    qualified_name, "unsupported".to_string(),
                    LocationType::Static, offset, 0,
                ));
                *seen_variable = true;
                continue;
            }
        }

        // ── Leaf property ───────────────────────────────────────────
        let in_type = unsafe { prop.Anonymous1.nonStructType.InType } as i32;

        // Read the raw TDH length before interpretation.
        let raw_len = unsafe { prop.Anonymous3.length } as usize;

        debug!(
            field = %qualified_name,
            in_type,
            flags = format!("0x{:x}", flags),
            raw_len,
            "TDH property leaf"
        );

        // Read the TDH-reported byte length for this property.
        //
        // When `PropertyParamLength` (0x2) is set, `Anonymous3` holds a
        // property *index* (parameterized length) — we must NOT interpret
        // it as a literal byte count.  In all other cases (including
        // `flags = 0x0`, common for TraceLoggingDynamic self-describing
        // fields with in_type >= 256), `Anonymous3.length` is a direct
        // byte count that TDH populates from the schema.
        // For variable-length in_types (counted strings, non-null-terminated
        // strings), never use the TDH-reported length as a fixed size because
        // it is per-event and the schema is cached.  Force these through the
        // dynamic LocationType path instead.
        let is_variable_intype = matches!(
            in_type,
            TDH_INTYPE_UNICODESTRING
            | TDH_INTYPE_ANSISTRING
            | TDH_INTYPE_MANIFEST_COUNTEDSTRING
            | TDH_INTYPE_MANIFEST_COUNTEDANSISTRING
            | TDH_INTYPE_COUNTEDSTRING
            | TDH_INTYPE_COUNTEDANSISTRING
            | TDH_INTYPE_REVERSEDCOUNTEDSTRING
            | TDH_INTYPE_REVERSEDCOUNTEDANSISTRING
            | TDH_INTYPE_NONNULLTERMINATEDSTRING
            | TDH_INTYPE_NONNULLTERMINATEDANSISTRING
        );

        let explicit_len: Option<usize> = if is_variable_intype {
            // Variable-length types must use their LocationType-specific
            // decoding (null-scan or length-prefix) rather than a cached
            // per-event byte count.
            None
        } else if (flags & PROPERTY_PARAM_LENGTH) == 0 {
            let len = raw_len;
            if len > 0 { Some(len) } else { None }
        } else {
            None
        };

        let offset = if *seen_variable { 0 } else { *running_offset };

        // If we have an explicit byte length, treat as fixed regardless
        // of the in_type.
        if let Some(len) = explicit_len {
            let type_name = intype_to_type_name(in_type);
            format.add_field(EventField::new(
                qualified_name, type_name.to_string(),
                LocationType::Static, offset, len,
            ));
            if !*seen_variable {
                *running_offset += len;
            }
            continue;
        }

        // Map TDH in-type to the framework's LocationType + size.
        let (type_name, loc, size) = intype_to_field_info(in_type, is_32bit);

        format.add_field(EventField::new(
            qualified_name, type_name.to_string(),
            loc, offset, size,
        ));

        if size == 0 {
            // Variable-length field: all subsequent offsets become 0.
            *seen_variable = true;
        } else if !*seen_variable {
            *running_offset += size;
        }
    }

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────

/// Finds the TraceLogging schema metadata in the event's extended-data.
///
/// Returns `None` when the event carries no (or an empty) SCHEMA_TL item,
/// which is the signal for [`TdhDecoder::decode`] to take the manifest path.
fn find_schema_tl(record: &EVENT_RECORD) -> Option<&[u8]> {
    let item_ptr = record
        .find_extended_data(EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16)?;
    let item = unsafe { &*item_ptr };
    if item.DataPtr == 0 || item.DataSize == 0 {
        return None;
    }
    Some(unsafe {
        std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
    })
}

/// Reads `TRACE_EVENT_INFO.DecodingSource` from a filled TEI buffer.
///
/// Used by the manifest dispatch path to reject non-XML-manifest sources
/// (WPP / WBEM) before they are cached under a `ManifestEventKey`.
fn read_decoding_source(tei_buf: &[u8]) -> Result<DECODING_SOURCE, TdhDecodeError> {
    if tei_buf.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return Err(TdhDecodeError::Malformed("buffer smaller than TRACE_EVENT_INFO"));
    }
    // SAFETY: the cast to `*const TRACE_EVENT_INFO` requires the buffer to be
    // suitably aligned.  Callers pass the `AlignedTeiBuf` backing store, whose
    // element type satisfies `TRACE_EVENT_INFO`'s alignment (guaranteed by the
    // const assertion next to `AlignedTeiBuf`).
    let tei = unsafe { &*(tei_buf.as_ptr() as *const TRACE_EVENT_INFO) };
    Ok(tei.DecodingSource)
}

/// Backing element type for [`AlignedTeiBuf`].  Its alignment must satisfy
/// `TRACE_EVENT_INFO`'s (checked by the const assertion below).
type TeiBufElem = u64;

// Guarantees every `AlignedTeiBuf` data pointer is suitably aligned for the
// `*const TRACE_EVENT_INFO` casts in `read_decoding_source` and
// `build_cached_schema`, so those reads stay sound.  If the backing element
// type ever changes to something under-aligned, the build fails here.
const _: () = assert!(
    std::mem::align_of::<TeiBufElem>() >= std::mem::align_of::<TRACE_EVENT_INFO>(),
    "AlignedTeiBuf backing element must satisfy TRACE_EVENT_INFO alignment"
);

/// Aligned buffer for `TRACE_EVENT_INFO`.
struct AlignedTeiBuf {
    storage: Vec<TeiBufElem>,
    len: usize,
}

impl AlignedTeiBuf {
    fn new() -> Self {
        Self { storage: Vec::new(), len: 0 }
    }

    fn ensure_capacity(&mut self, byte_count: usize) {
        let elem_size = std::mem::size_of::<TeiBufElem>();
        let elem_count = (byte_count + elem_size - 1) / elem_size;
        if self.storage.len() < elem_count {
            self.storage.resize(elem_count, 0);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self.storage.as_ptr() as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, self.len) }
    }

    fn as_mut_ptr(&mut self) -> *mut TRACE_EVENT_INFO {
        self.storage.as_mut_ptr() as *mut TRACE_EVENT_INFO
    }
}

/// Calls `TdhGetEventInformation`, growing the buffer as needed.
fn call_tdh_get_event_information(
    record: &EVENT_RECORD,
    buf: &mut AlignedTeiBuf,
) -> Result<(), TdhDecodeError> {
    let mut buffer_size: u32 = 0;
    let status = unsafe {
        TdhGetEventInformation(
            record as *const EVENT_RECORD, 0u32,
            core::ptr::null(), core::ptr::null_mut(), &mut buffer_size,
        )
    };
    if status == ERROR_NOT_FOUND {
        return Err(TdhDecodeError::NotFound);
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        warn!(win32_error = status, "TdhGetEventInformation sizing call failed");
        return Err(TdhDecodeError::Win32(status));
    }
    if buffer_size == 0 {
        return Err(TdhDecodeError::Malformed("TDH returned zero buffer size"));
    }
    buf.ensure_capacity(buffer_size as usize);
    let status = unsafe {
        TdhGetEventInformation(
            record as *const EVENT_RECORD, 0u32,
            core::ptr::null(), buf.as_mut_ptr(), &mut buffer_size,
        )
    };
    if status != 0 {
        warn!(win32_error = status, "TdhGetEventInformation fill call failed");
        return Err(TdhDecodeError::Win32(status));
    }
    buf.len = buffer_size as usize;
    trace!(buffer_size, "TdhGetEventInformation succeeded");
    Ok(())
}

// SAFETY guard for the `EventNameOffset` union read below.
// `TRACE_EVENT_INFO_0` is a union with two `u32` arms
// (`EventNameOffset` and `ActivityIDNameOffset`) at the same offset.
// Either arm always yields a valid bit pattern for a `u32`.
//
// Pin the union's layout to `u32`'s (both size *and* alignment) so the
// `tei.Anonymous1.EventNameOffset` read stays sound: a future `windows-sys`
// bump that grows the union or changes its alignment fails the build here
// rather than silently mis-reading the field.
const _: () = assert!(
    std::mem::size_of::<
        windows_sys::Win32::System::Diagnostics::Etw::TRACE_EVENT_INFO_0
    >() == std::mem::size_of::<u32>(),
    "TRACE_EVENT_INFO_0 union must stay the size of a u32",
);
const _: () = assert!(
    std::mem::align_of::<
        windows_sys::Win32::System::Diagnostics::Etw::TRACE_EVENT_INFO_0
    >() == std::mem::align_of::<u32>(),
    "TRACE_EVENT_INFO_0 union must stay u32-aligned",
);

/// Reads the event name from `TRACE_EVENT_INFO`, selecting the offset by
/// decoding source.
///
/// TraceLogging carries the name at `EventNameOffset`; manifest and WPP
/// events instead expose it as the task name at `TaskNameOffset`.  The
/// dispatch in [`TdhDecoder::decode`] only builds manifest schemas for
/// `DecodingSourceXMLFile`, so in practice this reads `EventNameOffset` for
/// TraceLogging and `TaskNameOffset` for manifest events.
fn read_event_name(tei_buf: &[u8], tei: &TRACE_EVENT_INFO) -> String {
    let name_offset = if tei.DecodingSource == DecodingSourceTlg {
        // SAFETY: Both arms of `TRACE_EVENT_INFO_0` are `u32` at the same
        // offset, so either arm always yields a valid bit pattern.  The
        // const assertion above guards the 4-byte size against future
        // `windows-sys` layout drift.
        unsafe { tei.Anonymous1.EventNameOffset as usize }
    } else {
        tei.TaskNameOffset as usize
    };
    read_utf16_at(tei_buf, name_offset)
}

/// Reads a null-terminated UTF-16 property name from the TEI buffer.
fn read_property_name(tei_buf: &[u8], prop: &EVENT_PROPERTY_INFO) -> String {
    read_utf16_at(tei_buf, prop.NameOffset as usize)
}

/// Reads a null-terminated UTF-16LE string from `buf` at `byte_offset`.
fn read_utf16_at(buf: &[u8], byte_offset: usize) -> String {
    if byte_offset == 0 || byte_offset >= buf.len() {
        return String::new();
    }
    let remaining = &buf[byte_offset..];
    let u16s: Vec<u16> = remaining
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Maps a TDH in-type to `(type_name, LocationType, size)`.
///
/// This is the single source of truth for the in-type → field-info
/// mapping, used by both `walk_properties` (schema construction) and
/// `intype_to_type_name` (explicit-length fallback).
pub(crate) const fn intype_to_field_info(in_type: i32, is_32bit: bool) -> (&'static str, LocationType, usize) {
    match in_type {
        // Fixed-size scalars
        TDH_INTYPE_INT8                          => ("s8",   LocationType::Static, 1),
        TDH_INTYPE_UINT8                         => ("u8",   LocationType::Static, 1),
        TDH_INTYPE_INT16                         => ("s16",  LocationType::Static, 2),
        TDH_INTYPE_UINT16                        => ("u16",  LocationType::Static, 2),
        TDH_INTYPE_INT32 | TDH_INTYPE_HEXINT32  => ("s32",  LocationType::Static, 4),
        TDH_INTYPE_UINT32                        => ("u32",  LocationType::Static, 4),
        // `TDH_INTYPE_BOOLEAN` is a Win32 `BOOL` — a 32-bit value
        // (TraceLogging `bool32`).  It is **not** a 1-byte boolean:
        // mapping it as `u8` would mis-size every subsequent field in
        // the same event.  TraceLogging encodes 1-byte booleans as
        // `TDH_INTYPE_UINT8` with `OutType::Boolean` (`bool8`).
        TDH_INTYPE_BOOLEAN                       => ("u32",  LocationType::Static, 4),
        TDH_INTYPE_INT64 | TDH_INTYPE_HEXINT64  => ("s64",  LocationType::Static, 8),
        TDH_INTYPE_UINT64                        => ("u64",  LocationType::Static, 8),
        TDH_INTYPE_FLOAT                         => ("float", LocationType::Static, 4),
        TDH_INTYPE_DOUBLE                        => ("double", LocationType::Static, 8),
        TDH_INTYPE_POINTER => {
            let sz = if is_32bit { 4 } else { 8 };
            ("pointer", LocationType::Static, sz)
        }
        TDH_INTYPE_FILETIME                      => ("filetime",   LocationType::Static, 8),
        TDH_INTYPE_SYSTEMTIME                    => ("systemtime", LocationType::Static, 16),
        TDH_INTYPE_GUID                          => ("guid",       LocationType::Static, 16),

        // Variable-length: null-terminated strings → size = 0
        TDH_INTYPE_ANSISTRING                    => ("string",  LocationType::StaticString, 0),
        TDH_INTYPE_UNICODESTRING                 => ("wstring", LocationType::StaticUTF16String, 0),

        // Counted strings (2-byte length prefix + content bytes).
        //
        // Two numeric families share this identical on-wire layout, so
        // they decode through the same `StaticLenPrefixArray` path:
        //   * Manifest range (22/23): emitted by `mc.exe` for manifest
        //     `CountedUnicodeString` / `CountedAnsiString` fields.
        //   * WBEM/WMI range (300/301): legacy WMI-sourced schemas.
        // TraceLogging self-describing events use the same in_type values,
        // so no separate handling is needed for the two decoding sources.
        TDH_INTYPE_MANIFEST_COUNTEDSTRING
        | TDH_INTYPE_COUNTEDSTRING               => ("counted_wstring", LocationType::StaticLenPrefixArray, 0),
        TDH_INTYPE_MANIFEST_COUNTEDANSISTRING
        | TDH_INTYPE_COUNTEDANSISTRING           => ("counted_string",  LocationType::StaticLenPrefixArray, 0),

        // Reversed-counted strings (length at end of data).
        // For TraceLogging the payload is typically null-terminated,
        // so we fall back to null-scan as a safe approximation.
        TDH_INTYPE_REVERSEDCOUNTEDSTRING         => ("wstring", LocationType::StaticUTF16String, 0),
        TDH_INTYPE_REVERSEDCOUNTEDANSISTRING     => ("string",  LocationType::StaticString, 0),

        // Non-null-terminated strings — scan for null as best effort.
        TDH_INTYPE_NONNULLTERMINATEDSTRING       => ("wstring", LocationType::StaticUTF16String, 0),
        TDH_INTYPE_NONNULLTERMINATEDANSISTRING   => ("string",  LocationType::StaticString, 0),

        // Variable-length: binary blobs, SID
        TDH_INTYPE_SID | TDH_INTYPE_BINARY      => ("binary", LocationType::Static, 0),

        // Unknown — treat as variable-length placeholder
        _ => ("unsupported", LocationType::Static, 0),
    }
}

/// Returns the type_name string for a TDH_INTYPE.
///
/// Delegates to [`intype_to_field_info`] and returns just the name.
const fn intype_to_type_name(in_type: i32) -> &'static str {
    intype_to_field_info(in_type, false).0
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::abi::EVENT_HEADER_EXTENDED_DATA_ITEM;

    #[test]
    fn type_name_scalars() {
        assert_eq!(intype_to_type_name(TDH_INTYPE_INT8), "s8");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UINT8), "u8");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UINT32), "u32");
        assert_eq!(intype_to_type_name(TDH_INTYPE_DOUBLE), "double");
        assert_eq!(intype_to_type_name(TDH_INTYPE_GUID), "guid");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UNICODESTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_ANSISTRING), "string");
        assert_eq!(intype_to_type_name(TDH_INTYPE_BINARY), "binary");
        assert_eq!(intype_to_type_name(999), "unsupported");
    }

    /// `TDH_INTYPE_BOOLEAN` is a Win32 `BOOL`, a 32-bit value
    /// (TraceLogging `bool32`).  Mapping it as `u8` (its previous
    /// behaviour) would mis-size every subsequent field in the same
    /// event.  TraceLogging encodes 1-byte booleans as
    /// `TDH_INTYPE_UINT8` with `OutType::Boolean` (`bool8`), which is
    /// covered by the `u8` case in `type_name_scalars`.
    #[test]
    fn type_name_boolean_is_u32() {
        assert_eq!(intype_to_type_name(TDH_INTYPE_BOOLEAN), "u32");
        let (name, loc, size) = intype_to_field_info(TDH_INTYPE_BOOLEAN, false);
        assert_eq!(name, "u32");
        assert_eq!(loc, LocationType::Static);
        assert_eq!(size, 4);
    }

    /// Verify that the extended TDH_INTYPE values 300-305 are all
    /// recognised as string types.  Per the windows-sys 0.59 constants,
    /// odd values (301, 303, 305) are ANSI and even values (300, 302,
    /// 304) are UTF-16.
    #[test]
    fn type_name_extended_strings() {
        // Counted string variants (2-byte length prefix)
        assert_eq!(intype_to_type_name(TDH_INTYPE_COUNTEDSTRING), "counted_wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_COUNTEDANSISTRING), "counted_string");
        // Manifest-range counted strings (22/23) share the same on-wire
        // layout as the WBEM range (300/301) and map identically.
        assert_eq!(intype_to_type_name(TDH_INTYPE_MANIFEST_COUNTEDSTRING), "counted_wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_MANIFEST_COUNTEDANSISTRING), "counted_string");
        // The LocationType is what actually drives decoding: both manifest
        // and WBEM counted strings must resolve to a 2-byte length-prefixed
        // array so the length prefix is consumed and following fields keep
        // their offsets.
        assert_eq!(
            intype_to_field_info(TDH_INTYPE_MANIFEST_COUNTEDSTRING, false),
            ("counted_wstring", LocationType::StaticLenPrefixArray, 0),
        );
        assert_eq!(
            intype_to_field_info(TDH_INTYPE_MANIFEST_COUNTEDANSISTRING, false),
            ("counted_string", LocationType::StaticLenPrefixArray, 0),
        );
        assert_eq!(
            intype_to_field_info(TDH_INTYPE_COUNTEDSTRING, false),
            ("counted_wstring", LocationType::StaticLenPrefixArray, 0),
        );
        // Reversed-counted → null-scan fallback
        assert_eq!(intype_to_type_name(TDH_INTYPE_REVERSEDCOUNTEDSTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_REVERSEDCOUNTEDANSISTRING), "string");
        // Non-null-terminated → null-scan fallback
        assert_eq!(intype_to_type_name(TDH_INTYPE_NONNULLTERMINATEDSTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_NONNULLTERMINATEDANSISTRING), "string");
    }

    #[test]
    fn read_utf16_at_basic() {
        let buf: Vec<u8> = vec![0xFF, 0xFF, b'A', 0, b'B', 0, 0, 0];
        assert_eq!(read_utf16_at(&buf, 2), "AB");
    }

    #[test]
    fn read_utf16_at_zero_offset() {
        assert_eq!(read_utf16_at(&[0x41, 0x00, 0x00, 0x00], 0), "");
    }

    #[test]
    fn read_utf16_at_out_of_bounds() {
        assert_eq!(read_utf16_at(&[0x41, 0x00], 100), "");
    }

    // ── End-to-end TDH integration tests ────────────────────────────

    /// TL InType constants (same as TDH_INTYPE_* values).
    const TL_UINT32: u8 = 8;
    const TL_UINT64: u8 = 10;
    const TL_DOUBLE: u8 = 12;
    const TL_ANSISTRING: u8 = 2;
    const TL_UNICODESTRING: u8 = 1;

    /// Builds a TraceLogging schema metadata blob.
    fn build_tl_schema(
        provider_name: &str,
        event_name: &str,
        fields: &[(&str, u8)],
    ) -> Vec<u8> {
        let mut blob = Vec::new();
        let prov_size = 2u16 + provider_name.len() as u16 + 1;
        blob.extend_from_slice(&prov_size.to_le_bytes());
        blob.extend_from_slice(provider_name.as_bytes());
        blob.push(0);
        let mut event_body_len: usize = 1 + event_name.len() + 1;
        for (name, _) in fields {
            event_body_len += name.len() + 1 + 1;
        }
        let event_size = 2u16 + event_body_len as u16;
        blob.extend_from_slice(&event_size.to_le_bytes());
        blob.push(0);
        blob.extend_from_slice(event_name.as_bytes());
        blob.push(0);
        for (name, intype) in fields {
            blob.extend_from_slice(name.as_bytes());
            blob.push(0);
            blob.push(*intype);
        }
        blob
    }

    const EXT_TYPE_PROV_TRAITS: u16 = 12;

    fn build_test_record(
        prov_blob: &[u8],
        event_blob: &[u8],
        ext_items: &mut [EVENT_HEADER_EXTENDED_DATA_ITEM; 2],
        user_data: &[u8],
    ) -> EVENT_RECORD {
        ext_items[0] = unsafe { std::mem::zeroed() };
        ext_items[0].ExtType = EXT_TYPE_PROV_TRAITS;
        ext_items[0].DataSize = prov_blob.len() as u16;
        ext_items[0].DataPtr = prov_blob.as_ptr() as u64;
        ext_items[1] = unsafe { std::mem::zeroed() };
        ext_items[1].ExtType = EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16;
        ext_items[1].DataSize = event_blob.len() as u16;
        ext_items[1].DataPtr = event_blob.as_ptr() as u64;
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 2;
        record.ExtendedData = ext_items.as_mut_ptr();
        record.UserData = user_data.as_ptr() as *mut std::ffi::c_void;
        record.UserDataLength = user_data.len() as u16;
        record
    }

    fn split_tl_schema(blob: &[u8]) -> (&[u8], &[u8]) {
        let prov_size = u16::from_le_bytes([blob[0], blob[1]]) as usize;
        (&blob[..prov_size], &blob[prov_size..])
    }

    #[test]
    fn tdh_decode_single_u32() {
        let schema = build_tl_schema("TestProvider", "SingleU32", &[
            ("ProcessId", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data: Vec<u8> = 42u32.to_le_bytes().to_vec();
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let _schema_id = result.schema_id;

        let fields = result.event_data.format().fields();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].location, LocationType::Static);
    }

    #[test]
    fn tdh_decode_multiple_scalars() {
        let schema = build_tl_schema("TestProvider", "MultiScalar", &[
            ("Code", TL_UINT32),
            ("Value", TL_DOUBLE),
            ("Count", TL_UINT64),
        ]);
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&100u32.to_le_bytes());
        user_data.extend_from_slice(&3.14f64.to_le_bytes());
        user_data.extend_from_slice(&999u64.to_le_bytes());

        let (prov, evt) = split_tl_schema(&schema);
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let event_data = &result.event_data;

        let fields = event_data.format().fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "Code");
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[1].name, "Value");
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 8);
        assert_eq!(fields[2].name, "Count");
        assert_eq!(fields[2].offset, 12);
        assert_eq!(fields[2].size, 8);
    }

    #[test]
    fn tdh_decode_with_ansi_string() {
        let schema = build_tl_schema("TestProvider", "WithString", &[
            ("Id", TL_UINT32),
            ("Message", TL_ANSISTRING),
            ("Flags", TL_UINT32),
        ]);
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&7u32.to_le_bytes());
        user_data.extend_from_slice(b"Hello\0");
        user_data.extend_from_slice(&0xFFu32.to_le_bytes());

        let (prov, evt) = split_tl_schema(&schema);
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let event_data = &result.event_data;

        let fields = event_data.format().fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "Id");
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[0].location, LocationType::Static);
        // Message: variable-length string with size = 0
        assert_eq!(fields[1].name, "Message");
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 0);
        assert_eq!(fields[1].location, LocationType::StaticString);
        // Flags: after a variable field, offset = 0
        assert_eq!(fields[2].name, "Flags");
        assert_eq!(fields[2].offset, 0);
        assert_eq!(fields[2].size, 4);

        // Verify the framework's lazy resolution works: read the Message
        // field using try_get_field_data_closure.
        let format = event_data.format();
        let mut msg_closure = format.try_get_field_data_closure("Message")
            .expect("should produce closure for Message");
        let msg_bytes = msg_closure(event_data.event_data());
        assert_eq!(msg_bytes, b"Hello");

        // Read the Flags field (after the variable string)
        let mut flags_closure = format.try_get_field_data_closure("Flags")
            .expect("should produce closure for Flags");
        let flags_bytes = flags_closure(event_data.event_data());
        assert_eq!(flags_bytes, &0xFFu32.to_le_bytes());
    }

    #[test]
    fn tdh_decode_with_unicode_string() {
        let schema = build_tl_schema("TestProvider", "WithWString", &[
            ("Name", TL_UNICODESTRING),
            ("Code", TL_UINT32),
        ]);
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&[b'A', 0, b'B', 0, 0, 0]); // "AB\0" UTF-16LE
        user_data.extend_from_slice(&42u32.to_le_bytes());

        let (prov, evt) = split_tl_schema(&schema);
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let event_data = &result.event_data;

        let fields = event_data.format().fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Name");
        assert_eq!(fields[0].size, 0); // variable
        assert_eq!(fields[0].location, LocationType::StaticUTF16String);
        assert_eq!(fields[1].name, "Code");
        assert_eq!(fields[1].offset, 0); // after variable field

        // Verify lazy resolution
        let format = event_data.format();
        let mut name_closure = format.try_get_field_data_closure("Name")
            .expect("should produce closure for Name");
        let name_bytes = name_closure(event_data.event_data());
        // StaticUTF16String returns bytes up to (not including) the null
        assert_eq!(name_bytes, &[b'A', 0, b'B', 0]);
    }

    #[test]
    fn tdh_decode_event_name() {
        let schema = build_tl_schema("MyProvider", "ImportantEvent", &[
            ("X", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data = 1u32.to_le_bytes();
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        assert_eq!(result.event_name, Some("ImportantEvent"));
    }

    #[test]
    fn tdh_decode_schema_cache_reuse() {
        let schema = build_tl_schema("TestProvider", "Cached", &[
            ("Val", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);

        let user_data_1 = 111u32.to_le_bytes();
        let mut ext_items_1: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_1 = build_test_record(prov, evt, &mut ext_items_1, &user_data_1);

        let mut decoder = TdhDecoder::new();
        let r1 = decoder.decode(&record_1).expect("first decode");
        let id1 = r1.schema_id;
        assert_eq!(r1.event_data.format().fields()[0].size, 4);

        let user_data_2 = 222u32.to_le_bytes();
        let mut ext_items_2: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_2 = build_test_record(prov, evt, &mut ext_items_2, &user_data_2);
        let r2 = decoder.decode(&record_2).expect("second decode (cached)");
        assert_eq!(r2.schema_id, id1, "cache hit should return same SchemaId");
        assert_eq!(r2.event_data.format().fields()[0].size, 4);
    }

    #[test]
    fn tdh_decode_distinct_schemas_interleaved() {
        // Exercises the index -> schema mapping introduced by the append-only
        // `schemas` Vec.  With multiple distinct schemas cached, a bug that
        // mixed up indices (e.g. always returning the last-inserted schema)
        // would be caught here but not by the single-schema cache tests.
        let schema_a = build_tl_schema("ProviderA", "EventA", &[
            ("A", TL_UINT32),
        ]);
        let schema_b = build_tl_schema("ProviderB", "EventB", &[
            ("B1", TL_UINT32),
            ("B2", TL_UINT32),
        ]);
        let (prov_a, evt_a) = split_tl_schema(&schema_a);
        let (prov_b, evt_b) = split_tl_schema(&schema_b);

        let mut decoder = TdhDecoder::new();

        // First decode of each schema populates the cache with two entries.
        let ud_a = 1u32.to_le_bytes();
        let mut ext_a: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_a = build_test_record(prov_a, evt_a, &mut ext_a, &ud_a);
        let ra = decoder.decode(&rec_a).expect("decode A");
        let id_a = ra.schema_id;
        assert_eq!(ra.event_name, Some("EventA"));
        assert_eq!(ra.event_data.format().fields().len(), 1);

        let ud_b = [3u32.to_le_bytes(), 4u32.to_le_bytes()].concat();
        let mut ext_b: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_b = build_test_record(prov_b, evt_b, &mut ext_b, &ud_b);
        let rb = decoder.decode(&rec_b).expect("decode B");
        let id_b = rb.schema_id;
        assert_eq!(rb.event_name, Some("EventB"));
        assert_eq!(rb.event_data.format().fields().len(), 2);
        assert_ne!(id_a, id_b, "distinct schemas must get distinct SchemaIds");

        // Re-decode in reversed order: both are cache hits and each must read
        // back its own schema, not the other's.
        let mut ext_b2: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_b2 = build_test_record(prov_b, evt_b, &mut ext_b2, &ud_b);
        let rb2 = decoder.decode(&rec_b2).expect("cache hit B");
        assert_eq!(rb2.schema_id, id_b, "B cache hit should map to B's schema");
        assert_eq!(rb2.event_name, Some("EventB"));
        assert_eq!(rb2.event_data.format().fields().len(), 2);

        let mut ext_a2: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_a2 = build_test_record(prov_a, evt_a, &mut ext_a2, &ud_a);
        let ra2 = decoder.decode(&rec_a2).expect("cache hit A");
        assert_eq!(ra2.schema_id, id_a, "A cache hit should map to A's schema");
        assert_eq!(ra2.event_name, Some("EventA"));
        assert_eq!(ra2.event_data.format().fields().len(), 1);
    }

    #[test]
    fn tdh_decode_not_found_without_schema_tl() {
        // A non-classic EVENT_RECORD with no SCHEMA_TL item takes the
        // manifest path.  With a zeroed (unregistered) provider GUID,
        // TdhGetEventInformation returns ERROR_NOT_FOUND, which surfaces as
        // TdhDecodeError::NotFound — the public-API contract for events
        // whose schema can't be resolved on this machine.
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 0;
        record.ExtendedData = std::ptr::null_mut();

        let mut decoder = TdhDecoder::new();
        match decoder.decode(&record) {
            Err(TdhDecodeError::NotFound) => {} // expected
            Err(other) => panic!("expected NotFound, got: {other}"),
            Ok(_) => panic!("expected NotFound error, but decode succeeded"),
        }
    }

    #[test]
    fn tdh_decode_pointer_width_cache_split() {
        // The same TL schema bytes under 32-bit and 64-bit headers
        // must produce two distinct cache entries because pointer
        // fields have different sizes (4 vs 8 bytes).
        let schema = build_tl_schema("TestProvider", "PtrEvent", &[
            ("Val", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data = 1u32.to_le_bytes();

        // 64-bit decode (default — flag not set)
        let mut ext_items_64: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_64 = build_test_record(prov, evt, &mut ext_items_64, &user_data);

        let mut decoder = TdhDecoder::new();
        let r64 = decoder.decode(&record_64).expect("64-bit decode");
        let id_64 = r64.schema_id;

        // 32-bit decode (set EVENT_HEADER_FLAG_32_BIT_HEADER)
        let mut ext_items_32: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let mut record_32 = build_test_record(prov, evt, &mut ext_items_32, &user_data);
        record_32.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;

        let r32 = decoder.decode(&record_32).expect("32-bit decode");
        let id_32 = r32.schema_id;
        assert_ne!(id_64, id_32, "32-bit and 64-bit should get different SchemaIds");

        // Second 64-bit decode should return the same SchemaId
        let mut ext_items_64b: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_64b = build_test_record(prov, evt, &mut ext_items_64b, &user_data);
        let r64b = decoder.decode(&record_64b).expect("64-bit cache hit");
        assert_eq!(r64b.schema_id, id_64, "64-bit cache hit should return same ID");

        // Second 32-bit decode should return the same SchemaId
        let mut ext_items_32b: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let mut record_32b = build_test_record(prov, evt, &mut ext_items_32b, &user_data);
        record_32b.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
        let r32b = decoder.decode(&record_32b).expect("32-bit cache hit");
        assert_eq!(r32b.schema_id, id_32, "32-bit cache hit should return same ID");
    }

    // ── Manifest-path tests ─────────────────────────────────────────

    /// Classic (MOF/WBEM) events must be fast-rejected before any TDH call:
    /// their identity is a class GUID + Opcode, not `(Provider, Id, Version)`,
    /// and their `Id` is commonly 0, so routing them through the manifest
    /// cache would collapse distinct events onto one key.
    #[test]
    fn tdh_decode_classic_header_rejected_before_tdh() {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 0;
        record.ExtendedData = std::ptr::null_mut();
        record.EventHeader.Flags |= EVENT_HEADER_FLAG_CLASSIC_HEADER;

        let mut decoder = TdhDecoder::new();
        match decoder.decode(&record) {
            Err(TdhDecodeError::Unsupported) => {} // expected — rejected during source classification
            Err(other) => panic!("expected Unsupported for classic header, got: {other}"),
            Ok(_) => panic!("expected Unsupported error, but decode succeeded"),
        }
    }

    /// `read_event_name` must pick `EventNameOffset` for TraceLogging and
    /// `TaskNameOffset` for manifest events, selected by `DecodingSource`.
    #[test]
    fn read_event_name_selects_offset_by_decoding_source() {
        fn push_utf16(buf: &mut Vec<u8>, s: &str) {
            for u in s.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&[0, 0]); // UTF-16 null terminator
        }

        // Layout: [TRACE_EVENT_INFO-sized header][EventName][TaskName].
        let mut buf = vec![0u8; std::mem::size_of::<TRACE_EVENT_INFO>()];
        let event_off = buf.len();
        push_utf16(&mut buf, "EventName");
        let task_off = buf.len();
        push_utf16(&mut buf, "TaskName");

        let mut tei: TRACE_EVENT_INFO = unsafe { std::mem::zeroed() };
        tei.TaskNameOffset = task_off as u32;
        // Writing a union field is safe; only reads are `unsafe`.
        tei.Anonymous1.EventNameOffset = event_off as u32;

        tei.DecodingSource = DecodingSourceTlg;
        assert_eq!(read_event_name(&buf, &tei), "EventName");

        tei.DecodingSource = DecodingSourceXMLFile;
        assert_eq!(read_event_name(&buf, &tei), "TaskName");
    }

    /// The manifest maps and the TraceLogging maps share one append-only
    /// arena but are indexed by different key types.  Verify that: entries
    /// never alias across sources, the 32-/64-bit split is honoured, and a
    /// duplicate manifest insert returns the existing index.
    #[test]
    fn manifest_cache_shared_arena_and_pointer_split() {
        let mk = |name: &str| CachedSchema {
            event_name: name.to_string(),
            format: EventFormat::new(),
            schema_id: SchemaId(0),
            provider_name: None,
            source: SchemaSourceKind::TraceLogging,
        };
        let key = ManifestEventKey {
            provider: Guid::from_u128(0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00),
            id: 5,
            version: 2,
        };

        let mut cache = SchemaCache::new();

        // 64-bit insert, then hit.
        let idx_a = cache.insert(SchemaSource::Manifest(key), false, mk("A"));
        assert_eq!(cache.index_of(&SchemaSource::Manifest(key), false), Some(idx_a));

        // The 32-bit map is a separate keyspace: same key misses there.
        assert_eq!(cache.index_of(&SchemaSource::Manifest(key), true), None);
        let idx_b = cache.insert(SchemaSource::Manifest(key), true, mk("B"));
        assert_ne!(idx_a, idx_b, "32-/64-bit split must yield distinct slots");

        // TraceLogging shares the arena but is indexed separately.
        let tl_idx = cache.insert(SchemaSource::TraceLogging(&[1, 2, 3]), false, mk("C"));
        assert_ne!(tl_idx, idx_a);
        assert_ne!(tl_idx, idx_b);
        assert_eq!(
            cache.index_of(&SchemaSource::TraceLogging(&[1, 2, 3]), false),
            Some(tl_idx)
        );

        // Each index reads back its own schema — no cross-source aliasing.
        assert_eq!(cache.get(idx_a).event_name, "A");
        assert_eq!(cache.get(idx_b).event_name, "B");
        assert_eq!(cache.get(tl_idx).event_name, "C");

        // A duplicate manifest insert returns the existing index and drops
        // the freshly built schema (no arena orphan).
        let before = cache.schemas.len();
        assert_eq!(
            cache.insert(SchemaSource::Manifest(key), false, mk("dup")),
            idx_a
        );
        assert_eq!(cache.schemas.len(), before, "duplicate must not grow arena");
        assert_eq!(cache.get(idx_a).event_name, "A", "original schema preserved");
    }

    /// The negative cache records permanently-unsupported manifest keys and
    /// is pointer-width independent (the decoding source doesn't depend on
    /// payload width).  Verify a marked key reports unsupported regardless of
    /// the `is_32bit` probe and that an unmarked key does not.
    #[test]
    fn manifest_unsupported_negative_cache() {
        let key = ManifestEventKey {
            provider: Guid::from_u128(0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF),
            id: 7,
            version: 1,
        };
        let other = ManifestEventKey {
            provider: key.provider,
            id: 8,
            version: 1,
        };

        let mut cache = SchemaCache::new();
        assert!(!cache.is_manifest_unsupported(&key));

        cache.mark_manifest_unsupported(key);
        assert!(cache.is_manifest_unsupported(&key), "marked key must report unsupported");
        assert!(!cache.is_manifest_unsupported(&other), "distinct key unaffected");

        // Marking is not a positive-cache entry: index lookups still miss.
        assert_eq!(cache.index_of(&SchemaSource::Manifest(key), false), None);
        assert_eq!(cache.index_of(&SchemaSource::Manifest(key), true), None);
    }

    /// `read_decoding_source` must reject a buffer smaller than
    /// `TRACE_EVENT_INFO` (its bounds check guards the subsequent
    /// `*const TRACE_EVENT_INFO` cast) and, for a well-formed buffer,
    /// return the exact `DecodingSource` value stored in it.
    #[test]
    fn read_decoding_source_bounds_and_value() {
        // Under-sized buffer → Malformed, and (crucially) the cast is never
        // reached, so an unaligned `Vec<u8>` here is fine.
        let too_small = vec![0u8; std::mem::size_of::<TRACE_EVENT_INFO>() - 1];
        match read_decoding_source(&too_small) {
            Err(TdhDecodeError::Malformed(_)) => {} // expected
            other => panic!("expected Malformed for under-sized buffer, got: {other:?}"),
        }

        // Value path: build a real, properly-aligned `TRACE_EVENT_INFO` on the
        // stack, then view it as bytes.  Deriving the slice from the struct's
        // own address guarantees the alignment `read_decoding_source` requires.
        fn tei_bytes(tei: &TRACE_EVENT_INFO) -> &[u8] {
            // SAFETY: `tei` is a live `TRACE_EVENT_INFO`, so the pointer is
            // valid, aligned, and spans exactly `size_of::<TRACE_EVENT_INFO>()`
            // initialized bytes for the borrow's lifetime.
            unsafe {
                std::slice::from_raw_parts(
                    tei as *const TRACE_EVENT_INFO as *const u8,
                    std::mem::size_of::<TRACE_EVENT_INFO>(),
                )
            }
        }

        let mut tei: TRACE_EVENT_INFO = unsafe { std::mem::zeroed() };

        tei.DecodingSource = DecodingSourceXMLFile;
        assert_eq!(read_decoding_source(tei_bytes(&tei)).unwrap(), DecodingSourceXMLFile);

        tei.DecodingSource = DecodingSourceTlg;
        assert_eq!(read_decoding_source(tei_bytes(&tei)).unwrap(), DecodingSourceTlg);
    }

    /// TraceLogging inserts mirror the manifest single-hash vacancy semantics:
    /// a duplicate `insert` returns the existing index without growing the
    /// arena (no orphaned schema), and the 32-/64-bit maps stay separate
    /// keyspaces for identical bytes.
    #[test]
    fn tracelogging_duplicate_key_returns_existing_index() {
        let mk = |name: &str| CachedSchema {
            event_name: name.to_string(),
            format: EventFormat::new(),
            schema_id: SchemaId(0),
            provider_name: None,
            source: SchemaSourceKind::TraceLogging,
        };

        let mut cache = SchemaCache::new();

        let idx = cache.insert(SchemaSource::TraceLogging(&[9, 8, 7]), false, mk("first"));
        assert_eq!(
            cache.index_of(&SchemaSource::TraceLogging(&[9, 8, 7]), false),
            Some(idx)
        );

        // Duplicate insert returns the existing index and drops the freshly
        // built schema — the arena must not grow.
        let before = cache.schemas.len();
        assert_eq!(
            cache.insert(SchemaSource::TraceLogging(&[9, 8, 7]), false, mk("dup")),
            idx
        );
        assert_eq!(cache.schemas.len(), before, "duplicate must not grow arena");
        assert_eq!(cache.get(idx).event_name, "first", "original schema preserved");

        // The 32-bit map is a separate keyspace: the same bytes miss there.
        assert_eq!(cache.index_of(&SchemaSource::TraceLogging(&[9, 8, 7]), true), None);
    }

    // ── EventSource in-band manifest dispatch tests ─────────────────

    use super::super::eventsource::envelope::build_chunk;
    use super::super::eventsource::manifest::{TEST_MANIFEST, TEST_PROVIDER};

    /// Builds a non-TraceLogging record (no extended data) for `provider`.
    fn es_record(
        provider: Guid,
        pid: u32,
        (id, version, opcode, task): (u16, u8, u8, u16),
        user_data: &[u8],
    ) -> EVENT_RECORD {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        // SAFETY: `Guid` and `windows_sys::core::GUID` are layout-identical
        // (asserted in `abi.rs`).
        record.EventHeader.ProviderId = unsafe { std::mem::transmute::<Guid, windows_sys::core::GUID>(provider) };
        record.EventHeader.ProcessId = pid;
        record.EventHeader.ThreadId = 1;
        record.EventHeader.EventDescriptor.Id = id;
        record.EventHeader.EventDescriptor.Version = version;
        record.EventHeader.EventDescriptor.Opcode = opcode;
        record.EventHeader.EventDescriptor.Task = task;
        record.UserData = user_data.as_ptr() as *mut std::ffi::c_void;
        record.UserDataLength = user_data.len() as u16;
        record
    }

    const MANIFEST_DESC: (u16, u8, u8, u16) = (0xFFFE, 1, 0xFE, 0xFFFE);

    /// Sends `xml` as `chunks` manifest chunk events from `pid`, asserting
    /// each is reported as `InbandManifest`.
    fn feed_manifest(decoder: &mut TdhDecoder, provider: Guid, pid: u32, xml: &[u8], chunks: usize) {
        let size = xml.len().div_ceil(chunks);
        let parts: Vec<&[u8]> = xml.chunks(size).collect();
        for (n, part) in parts.iter().enumerate() {
            let payload = build_chunk(parts.len() as u16, n as u16, part);
            let record = es_record(provider, pid, MANIFEST_DESC, &payload);
            assert!(matches!(decoder.decode(&record), Err(TdhDecodeError::InbandManifest)));
        }
    }

    fn values<'a>(event: &'a TdhDecodedEvent<'a>) -> Vec<(&'a str, &'a [u8])> {
        event.event_data.format()
            .fields_with_data(event.event_data.event_data())
            .map(|(f, bytes)| (f.name.as_str(), bytes))
            .collect()
    }

    fn utf16z(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn inband_manifest_decodes_all_scalars() {
        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 3);

        let mut payload = Vec::new();
        payload.extend_from_slice(&(-8i8).to_le_bytes());
        payload.extend_from_slice(&0xABu8.to_le_bytes());
        payload.extend_from_slice(&(-1600i16).to_le_bytes());
        payload.extend_from_slice(&0xBEEFu16.to_le_bytes());
        payload.extend_from_slice(&(-32_000_000i32).to_le_bytes());
        payload.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        payload.extend_from_slice(&(-6_400_000_000_000i64).to_le_bytes());
        payload.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
        payload.extend_from_slice(&3.5f32.to_le_bytes());
        payload.extend_from_slice(&2.25f64.to_le_bytes());
        payload.extend_from_slice(&1i32.to_le_bytes()); // win:Boolean = 4-byte BOOL
        payload.extend_from_slice(&(b'Z' as u16).to_le_bytes());

        let record = es_record(TEST_PROVIDER, 10, (1, 0, 0, 0xFFFD), &payload);
        let event = decoder.decode(&record).expect("in-band decode");

        assert_eq!(event.source, SchemaSourceKind::InbandManifest);
        assert_eq!(event.event_name, Some("AllScalars"));
        assert_eq!(event.provider_name, Some("OneCollect-Test-InbandManifest"));

        let v = values(&event);
        assert_eq!(v.len(), 12);
        assert_eq!(v[0], ("s8", &(-8i8).to_le_bytes()[..]));
        assert_eq!(v[3], ("u16", &0xBEEFu16.to_le_bytes()[..]));
        assert_eq!(v[7], ("u64", &0x0102030405060708u64.to_le_bytes()[..]));
        assert_eq!(v[9], ("f64", &2.25f64.to_le_bytes()[..]));
        assert_eq!(v[10], ("b", &1i32.to_le_bytes()[..]));
        assert_eq!(v[11], ("c", &(b'Z' as u16).to_le_bytes()[..]));
        assert_eq!(event.event_data.format().fields()[10].type_name, "u32");

        let stats = decoder.inband_manifest_stats();
        assert_eq!(stats.chunks, 3);
        assert_eq!(stats.manifests_completed, 1);
        assert_eq!(stats.ingest_errors(), 0);
    }

    #[test]
    fn inband_manifest_decodes_strings_blob_and_parameterless() {
        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 1);

        // Strings(string first, string empty, int after)
        let mut payload = utf16z("hello-inband");
        payload.extend(utf16z(""));
        payload.extend_from_slice(&1234i32.to_le_bytes());
        let record = es_record(TEST_PROVIDER, 10, (2, 0, 0, 0xFFFC), &payload);
        let event = decoder.decode(&record).unwrap();
        let v = values(&event);
        let hello: Vec<u8> = "hello-inband".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(v[0], ("first", &hello[..]));
        assert_eq!(v[1], ("empty", &[][..]));
        assert_eq!(v[2], ("after", &1234i32.to_le_bytes()[..]));

        // Blob(int before, byte[] data, int after): data is u32 len + bytes.
        let mut payload = 7i32.to_le_bytes().to_vec();
        payload.extend_from_slice(&5u32.to_le_bytes());
        payload.extend_from_slice(&[1, 2, 3, 4, 5]);
        payload.extend_from_slice(&9i32.to_le_bytes());
        let record = es_record(TEST_PROVIDER, 10, (4, 0, 0, 0xFFF9), &payload);
        let event = decoder.decode(&record).unwrap();
        assert_eq!(values(&event), vec![
            ("before", &7i32.to_le_bytes()[..]),
            ("data", &[1, 2, 3, 4, 5][..]),
            ("after", &9i32.to_le_bytes()[..]),
        ]);
        assert_eq!(event.event_data.format().fields()[1].type_name, "binary");

        // Ping(): no template, empty payload.
        let record = es_record(TEST_PROVIDER, 10, (5, 0, 0, 0xFFF9), &[]);
        let event = decoder.decode(&record).unwrap();
        assert_eq!(event.event_name, Some("Ping"));
        assert!(event.event_data.format().fields().is_empty());

        // Start/Stop share a task but report their symbol names.
        let payload = 42i32.to_le_bytes();
        let start = es_record(TEST_PROVIDER, 10, (6, 0, 1, 1), &payload);
        assert_eq!(decoder.decode(&start).unwrap().event_name, Some("RequestStart"));
        let stop = es_record(TEST_PROVIDER, 10, (7, 0, 2, 1), &payload);
        assert_eq!(decoder.decode(&stop).unwrap().event_name, Some("RequestStop"));
    }

    #[test]
    fn tracelogging_event_from_inband_provider_takes_tl_path() {
        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 1);

        // Same provider GUID and an Id the manifest defines, but the event
        // carries SCHEMA_TL: it must decode via TraceLogging.
        let schema = build_tl_schema("OneCollect-Test-InbandManifest", "MixedTl", &[("Value", TL_UINT32)]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data = 4242u32.to_le_bytes();
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let mut record = build_test_record(prov, evt, &mut ext_items, &user_data);
        record.EventHeader.ProviderId = unsafe { std::mem::transmute::<Guid, windows_sys::core::GUID>(TEST_PROVIDER) };
        record.EventHeader.ProcessId = 10;
        record.EventHeader.EventDescriptor.Id = 1;

        let event = decoder.decode(&record).expect("TL decode");
        assert_eq!(event.source, SchemaSourceKind::TraceLogging);
        assert_eq!(event.event_name, Some("MixedTl"));
        assert_eq!(event.provider_name, None);
    }

    #[test]
    fn events_before_manifest_and_undefined_ids_fall_through() {
        let mut decoder = TdhDecoder::new();
        let payload = 1i32.to_le_bytes();

        // Before any manifest: OS-registered path → NotFound.
        let record = es_record(TEST_PROVIDER, 10, (6, 0, 1, 1), &payload);
        assert!(matches!(decoder.decode(&record), Err(TdhDecodeError::NotFound)));

        // Partial manifest only: still NotFound.
        let half = &TEST_MANIFEST.as_bytes()[..100];
        let chunk = build_chunk(2, 0, half);
        let chunk_record = es_record(TEST_PROVIDER, 10, MANIFEST_DESC, &chunk);
        assert!(matches!(decoder.decode(&chunk_record), Err(TdhDecodeError::InbandManifest)));
        assert!(matches!(decoder.decode(&record), Err(TdhDecodeError::NotFound)));

        // After the manifest: decodes; an Id it doesn't define falls through.
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 2);
        assert!(decoder.decode(&record).is_ok());
        let undefined = es_record(TEST_PROVIDER, 10, (99, 0, 0, 0), &payload);
        assert!(matches!(decoder.decode(&undefined), Err(TdhDecodeError::NotFound)));
        // Version mismatch also falls through (event 8 only exists at v2).
        let wrong_version = es_record(TEST_PROVIDER, 10, (8, 0, 0, 0), &payload);
        assert!(matches!(decoder.decode(&wrong_version), Err(TdhDecodeError::NotFound)));
        let right_version = es_record(TEST_PROVIDER, 10, (8, 2, 0, 0), &payload);
        assert_eq!(decoder.decode(&right_version).unwrap().event_name, Some("Versioned"));
    }

    #[test]
    fn malformed_chunks_are_still_reported_as_inband_manifest() {
        let mut decoder = TdhDecoder::new();

        let mut bad_magic = build_chunk(1, 0, b"<x/>");
        bad_magic[3] = 0;
        let record = es_record(TEST_PROVIDER, 10, MANIFEST_DESC, &bad_magic);
        assert!(matches!(decoder.decode(&record), Err(TdhDecodeError::InbandManifest)));

        let orphan = build_chunk(3, 2, b"zz");
        let record = es_record(TEST_PROVIDER, 10, MANIFEST_DESC, &orphan);
        assert!(matches!(decoder.decode(&record), Err(TdhDecodeError::InbandManifest)));

        let bad_xml = build_chunk(1, 0, b"<events><provider");
        let record = es_record(TEST_PROVIDER, 10, MANIFEST_DESC, &bad_xml);
        assert!(matches!(decoder.decode(&record), Err(TdhDecodeError::InbandManifest)));

        let stats = decoder.inband_manifest_stats();
        assert_eq!(stats.chunks, 3);
        assert_eq!(stats.envelope_errors, 1);
        assert_eq!(stats.orphan_chunks, 1);
        assert_eq!(stats.xml_errors, 1);
        assert_eq!(stats.ingest_errors(), 3);
    }

    #[test]
    fn inband_schema_ids_pointer_width_and_identical_processes() {
        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 1);
        feed_manifest(&mut decoder, TEST_PROVIDER, 20, TEST_MANIFEST.as_bytes(), 2);

        // Misc(Guid, DateTime, IntPtr, enum)
        let payload_64 = [0u8; 16 + 8 + 8 + 4];
        let payload_32 = [0u8; 16 + 8 + 4 + 4];

        let r64 = es_record(TEST_PROVIDER, 10, (3, 0, 0, 0), &payload_64);
        let (id_64, ptr_64) = {
            let e = decoder.decode(&r64).unwrap();
            (e.schema_id, e.event_data.format().fields()[2].size)
        };

        let mut r32 = es_record(TEST_PROVIDER, 10, (3, 0, 0, 0), &payload_32);
        r32.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
        let (id_32, ptr_32) = {
            let e = decoder.decode(&r32).unwrap();
            (e.schema_id, e.event_data.format().fields()[2].size)
        };

        assert_ne!(id_64, id_32);
        assert_eq!((ptr_64, ptr_32), (8, 4));

        // A different process with an identical manifest shares the schema.
        let other = es_record(TEST_PROVIDER, 20, (3, 0, 0, 0), &payload_64);
        assert_eq!(decoder.decode(&other).unwrap().schema_id, id_64);
        // Identical re-send keeps SchemaIds stable.
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 1);
        assert_eq!(decoder.decode(&r64).unwrap().schema_id, id_64);
    }

    #[test]
    fn rebinding_purges_cached_schemas_and_reuses_slots() {
        let manifest = |ty: &str| format!(r#"<events><provider name="P" guid="{{369e340b-d54c-5d95-1211-b7a318f16882}}">
<events><event value="1" symbol="E" template="T"/></events>
<templates><template tid="T"><data name="v" inType="{ty}"/></template></templates>
</provider></events>"#);

        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, manifest("win:UInt32").as_bytes(), 1);

        let payload = 5u64.to_le_bytes();
        let record = es_record(TEST_PROVIDER, 10, (1, 0, 0, 0), &payload);
        let first_id = {
            let e = decoder.decode(&record).unwrap();
            assert_eq!(e.event_data.format().fields()[0].size, 4);
            e.schema_id
        };
        let slots = decoder.cache.schemas.len();

        // The same process re-emits a different manifest (new build).
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, manifest("win:UInt64").as_bytes(), 1);
        assert!(decoder.cache.inband_64.is_empty(), "old schemas purged");
        assert_eq!(decoder.cache.free.len(), 1);

        let e = decoder.decode(&record).unwrap();
        assert_eq!(e.event_data.format().fields()[0].size, 8, "new layout used");
        assert_ne!(e.schema_id, first_id, "SchemaIds are never reused");
        assert_eq!(decoder.cache.schemas.len(), slots, "freed slot was recycled");
    }

    #[test]
    fn unbound_process_uses_agreed_manifest_only_after_os_lookup_misses() {
        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, TEST_MANIFEST.as_bytes(), 1);

        let payload = 42i32.to_le_bytes();
        let os_key = ManifestEventKey { provider: TEST_PROVIDER, id: 6, version: 0 };

        // PID 30 sent no manifest.  The OS lookup runs first (NotFound for
        // this unregistered provider), then the agreed manifest is used.
        let unbound = es_record(TEST_PROVIDER, 30, (6, 0, 1, 1), &payload);
        assert!(!decoder.os_manifest_absent.contains(&os_key));
        let first = {
            let e = decoder.decode(&unbound).expect("fallback decode");
            assert_eq!(e.source, SchemaSourceKind::InbandManifest);
            assert_eq!(e.event_name, Some("RequestStart"));
            e.schema_id
        };
        assert!(decoder.os_manifest_absent.contains(&os_key), "OS miss memoized");

        // Later events skip the OS lookup and share the bound process's schema.
        assert_eq!(decoder.decode(&unbound).unwrap().schema_id, first);
        let bound = es_record(TEST_PROVIDER, 10, (6, 0, 1, 1), &payload);
        assert_eq!(decoder.decode(&bound).unwrap().schema_id, first);
    }

    #[test]
    fn conflicting_manifests_are_not_guessed_for_unbound_process() {
        let manifest = |ty: &str| format!(r#"<events><provider name="P" guid="{{369e340b-d54c-5d95-1211-b7a318f16882}}">
<events><event value="1" symbol="E" template="T"/></events>
<templates><template tid="T"><data name="v" inType="{ty}"/></template></templates>
</provider></events>"#);

        let mut decoder = TdhDecoder::new();
        feed_manifest(&mut decoder, TEST_PROVIDER, 10, manifest("win:UInt32").as_bytes(), 1);
        feed_manifest(&mut decoder, TEST_PROVIDER, 20, manifest("win:UInt64").as_bytes(), 1);

        let payload = 5u64.to_le_bytes();
        let p10 = es_record(TEST_PROVIDER, 10, (1, 0, 0, 0), &payload);
        let p20 = es_record(TEST_PROVIDER, 20, (1, 0, 0, 0), &payload);
        let p30 = es_record(TEST_PROVIDER, 30, (1, 0, 0, 0), &payload);

        assert_eq!(decoder.decode(&p10).unwrap().event_data.format().fields()[0].size, 4);
        assert_eq!(decoder.decode(&p20).unwrap().event_data.format().fields()[0].size, 8);
        assert!(matches!(decoder.decode(&p30), Err(TdhDecodeError::NotFound)));
    }
}
