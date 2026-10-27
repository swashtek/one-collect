// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parsing of EventSource (`ManifestBuilder`) XML manifests into event
//! definitions, and conversion of those definitions into [`EventFormat`]s.
//!
//! Only what decoding needs is extracted: the provider identity, each
//! `<event>`'s `(value, version)`, its name (`symbol`, falling back to
//! `task`), and its template's ordered `<data>` fields.  Maps, keywords,
//! channels, opcodes and localized strings are ignored, so integer values stay
//! raw (consistent with the OS-registered manifest path).
//!
//! References are resolved after a single streaming pass, so element order
//! within the manifest does not matter.

use std::collections::HashMap;
use std::sync::Arc;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use windows_sys::Win32::System::Diagnostics::Etw::{
    TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_DOUBLE,
    TDH_INTYPE_FILETIME,
    TDH_INTYPE_FLOAT,
    TDH_INTYPE_GUID,
    TDH_INTYPE_HEXINT32,
    TDH_INTYPE_HEXINT64,
    TDH_INTYPE_INT16,
    TDH_INTYPE_INT32,
    TDH_INTYPE_INT64,
    TDH_INTYPE_INT8,
    TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
    TDH_INTYPE_MANIFEST_COUNTEDSTRING,
    TDH_INTYPE_POINTER,
    TDH_INTYPE_SID,
    TDH_INTYPE_SYSTEMTIME,
    TDH_INTYPE_UINT16,
    TDH_INTYPE_UINT32,
    TDH_INTYPE_UINT64,
    TDH_INTYPE_UINT8,
    TDH_INTYPE_UNICODESTRING,
};

use super::XxBuildHasher;
use crate::Guid;
use crate::etw::tdh::intype_to_field_info;
use crate::event::{EventField, EventFormat, LocationType};

/// Maximum number of `<event>` definitions accepted in one manifest.
pub(crate) const MAX_EVENTS: usize = 65536;
/// Maximum number of fields in one template.
pub(crate) const MAX_FIELDS_PER_TEMPLATE: usize = 1024;
/// Maximum length (bytes) of any name or attribute value we retain.
pub(crate) const MAX_NAME_LEN: usize = 1024;
/// Largest fixed `win:Binary length="N"` accepted (ETW events are < 64 KiB).
const MAX_FIXED_BINARY: usize = u16::MAX as usize;

/// How a single template field is laid out on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FieldKind {
    /// A TDH in-type, sized via [`intype_to_field_info`].
    InType(i32),
    /// `win:Binary` whose length is the immediately preceding `u32`/`i32`
    /// field (EventSource `byte[]`): a u32 length prefix + bytes.
    Blob32,
    /// `win:Binary` with a literal fixed length.
    FixedBinary(usize),
    /// Unsupported layout (array, struct, unknown type, or a length given by
    /// a non-adjacent field).  Fields after it cannot be located.
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FieldDef {
    pub(crate) name: String,
    pub(crate) kind: FieldKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EventDef {
    /// `symbol` (EventSource method name), else `task`, else empty.
    pub(crate) name: String,
    /// Shared by every event that references the same template, so parsed
    /// size stays proportional to the manifest's size.
    pub(crate) fields: Arc<[FieldDef]>,
}

pub(crate) struct ProviderManifest {
    pub(crate) name: String,
    /// Keyed by `(EVENT_DESCRIPTOR.Id, EVENT_DESCRIPTOR.Version)`.
    pub(crate) events: HashMap<(u16, u8), EventDef, XxBuildHasher>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ManifestError {
    NotUtf8,
    /// Not well-formed XML, or an attribute value could not be decoded.
    Xml(String),
    /// No `<provider>` whose `guid` matches the emitting provider.
    NoMatchingProvider,
    /// A count or length limit was exceeded.
    TooLarge(&'static str),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "manifest is not valid UTF-8"),
            Self::Xml(e) => write!(f, "malformed manifest XML: {e}"),
            Self::NoMatchingProvider => write!(f, "manifest has no provider matching the emitting provider GUID"),
            Self::TooLarge(what) => write!(f, "manifest limit exceeded: {what}"),
        }
    }
}

/// A `<data>` or `<struct>` entry of a template, before resolution.
enum TemplateItem {
    Data {
        name: String,
        in_type: String,
        length: Option<String>,
        count: Option<String>,
    },
    Struct {
        name: String,
    },
}

struct RawEvent {
    value: u16,
    version: u8,
    name: String,
    template: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Elem {
    Provider,
    Events,
    Templates,
    Template,
    Struct,
    Other,
}

fn classify(local_name: &[u8]) -> Elem {
    match local_name {
        b"provider" => Elem::Provider,
        b"events" => Elem::Events,
        b"templates" => Elem::Templates,
        b"template" => Elem::Template,
        b"struct" => Elem::Struct,
        _ => Elem::Other,
    }
}

/// Selected attributes of one element.
#[derive(Default)]
struct Attrs {
    name: Option<String>,
    guid: Option<String>,
    value: Option<String>,
    version: Option<String>,
    symbol: Option<String>,
    task: Option<String>,
    template: Option<String>,
    tid: Option<String>,
    in_type: Option<String>,
    length: Option<String>,
    count: Option<String>,
}

fn read_attrs(e: &BytesStart<'_>, reader: &Reader<&[u8]>) -> Result<Attrs, ManifestError> {
    let mut attrs = Attrs::default();

    for attr in e.attributes() {
        let attr = attr.map_err(|e| ManifestError::Xml(e.to_string()))?;
        let slot = match attr.key.local_name().as_ref() {
            b"name" => &mut attrs.name,
            b"guid" => &mut attrs.guid,
            b"value" => &mut attrs.value,
            b"version" => &mut attrs.version,
            b"symbol" => &mut attrs.symbol,
            b"task" => &mut attrs.task,
            b"template" => &mut attrs.template,
            b"tid" => &mut attrs.tid,
            b"inType" => &mut attrs.in_type,
            b"length" => &mut attrs.length,
            b"count" => &mut attrs.count,
            _ => continue,
        };

        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|e| ManifestError::Xml(e.to_string()))?;
        if value.len() > MAX_NAME_LEN {
            return Err(ManifestError::TooLarge("attribute value length"));
        }
        *slot = Some(value.into_owned());
    }

    Ok(attrs)
}

/// Parses a `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` GUID (braces optional).
pub(crate) fn parse_guid(s: &str) -> Option<Guid> {
    let s = s.trim();
    let s = s.strip_prefix('{').unwrap_or(s);
    let s = s.strip_suffix('}').unwrap_or(s);

    let parts: Vec<&str> = s.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    if parts.len() != lens.len()
        || parts.iter().zip(lens).any(|(p, l)| p.len() != l || !p.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }

    u128::from_str_radix(&parts.concat(), 16).ok().map(Guid::from_u128)
}

fn parse_number<T: TryFrom<u64>>(s: &str) -> Option<T> {
    let s = s.trim();
    let n = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => s.parse::<u64>().ok()?,
    };
    T::try_from(n).ok()
}

/// Maps a manifest `inType` to a TDH in-type.
fn map_in_type(in_type: &str) -> Option<i32> {
    Some(match in_type {
        "win:Int8" => TDH_INTYPE_INT8,
        "win:UInt8" => TDH_INTYPE_UINT8,
        "win:Int16" => TDH_INTYPE_INT16,
        "win:UInt16" => TDH_INTYPE_UINT16,
        "win:Int32" => TDH_INTYPE_INT32,
        "win:UInt32" => TDH_INTYPE_UINT32,
        "win:Int64" => TDH_INTYPE_INT64,
        "win:UInt64" => TDH_INTYPE_UINT64,
        "win:Float" => TDH_INTYPE_FLOAT,
        "win:Double" => TDH_INTYPE_DOUBLE,
        "win:Boolean" => TDH_INTYPE_BOOLEAN,
        "win:GUID" => TDH_INTYPE_GUID,
        "win:Pointer" | "trace:SizeT" => TDH_INTYPE_POINTER,
        "win:FILETIME" => TDH_INTYPE_FILETIME,
        "win:SYSTEMTIME" => TDH_INTYPE_SYSTEMTIME,
        "win:SID" => TDH_INTYPE_SID,
        "win:HexInt32" => TDH_INTYPE_HEXINT32,
        "win:HexInt64" => TDH_INTYPE_HEXINT64,
        "win:UnicodeString" => TDH_INTYPE_UNICODESTRING,
        "win:AnsiString" => TDH_INTYPE_ANSISTRING,
        "win:CountedUnicodeString" => TDH_INTYPE_MANIFEST_COUNTEDSTRING,
        "win:CountedAnsiString" => TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
        _ => return None,
    })
}

/// Resolves a template's raw items into field layouts.
fn resolve_fields(items: &[TemplateItem]) -> Vec<FieldDef> {
    let mut fields: Vec<FieldDef> = Vec::with_capacity(items.len());

    for item in items {
        let (name, kind) = match item {
            TemplateItem::Struct { name } => (name.clone(), FieldKind::Unsupported),
            TemplateItem::Data { name, in_type, length, count } => {
                let kind = if count.is_some() {
                    FieldKind::Unsupported
                } else if in_type == "win:Binary" {
                    match length.as_deref() {
                        Some(len) => match parse_number::<usize>(len) {
                            Some(n) if n > 0 && n <= MAX_FIXED_BINARY => FieldKind::FixedBinary(n),
                            Some(_) => FieldKind::Unsupported,
                            None => {
                                // EventSource `byte[]`: `xSize` (u32) then
                                // `x` (win:Binary length="xSize").  Fuse the
                                // pair into one u32-prefixed blob field.
                                let fusable = fields.last().is_some_and(|prev| {
                                    prev.name == len
                                        && matches!(prev.kind, FieldKind::InType(t)
                                            if t == TDH_INTYPE_UINT32 || t == TDH_INTYPE_INT32)
                                });
                                if fusable {
                                    fields.pop();
                                    FieldKind::Blob32
                                } else {
                                    FieldKind::Unsupported
                                }
                            }
                        },
                        None => FieldKind::Unsupported,
                    }
                } else if length.is_some() {
                    FieldKind::Unsupported
                } else {
                    map_in_type(in_type).map_or(FieldKind::Unsupported, FieldKind::InType)
                };
                (name.clone(), kind)
            }
        };

        fields.push(FieldDef { name, kind });
    }

    fields
}

/// Parses an EventSource manifest, keeping only the `<provider>` whose
/// `guid` equals `expected` (a stream may not install schemas under another
/// provider's identity).
pub(crate) fn parse(bytes: &[u8], expected: &Guid) -> Result<ProviderManifest, ManifestError> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| ManifestError::NotUtf8)?;

    let mut reader = Reader::from_str(text);
    reader.config_mut().check_end_names = true;

    let mut stack: Vec<Elem> = Vec::new();
    let mut provider_name: Option<String> = None;
    // Whether the innermost open <provider> is the one we are collecting.
    let mut in_matching_provider = false;

    let mut raw_events: Vec<RawEvent> = Vec::new();
    let mut templates: HashMap<String, Vec<TemplateItem>> = HashMap::new();
    let mut current_template: Option<(String, Vec<TemplateItem>)> = None;

    loop {
        let event = reader.read_event().map_err(|e| ManifestError::Xml(e.to_string()))?;

        let (e, is_empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::End(_) => {
                match stack.pop() {
                    Some(Elem::Provider) => in_matching_provider = false,
                    Some(Elem::Template) => {
                        if let Some((tid, items)) = current_template.take() {
                            templates.entry(tid).or_insert(items);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(ManifestError::Xml("unexpected end of document".into()));
                }
                break;
            }
            _ => continue,
        };

        let elem = classify(e.local_name().as_ref());
        let parent = stack.last().copied();
        let grandparent = stack.len().checked_sub(2).map(|i| stack[i]);

        match elem {
            Elem::Provider => {
                let attrs = read_attrs(e, &reader)?;
                let matches = provider_name.is_none()
                    && attrs.guid.as_deref().and_then(parse_guid).as_ref() == Some(expected);
                if matches {
                    provider_name = Some(attrs.name.unwrap_or_default());
                }
                in_matching_provider = matches && !is_empty;
            }

            Elem::Other if in_matching_provider
                && e.local_name().as_ref() == b"event"
                && parent == Some(Elem::Events)
                && grandparent == Some(Elem::Provider) => {
                let attrs = read_attrs(e, &reader)?;
                // An event without a parseable value cannot be keyed; skip it.
                let Some(value) = attrs.value.as_deref().and_then(parse_number::<u16>) else {
                    continue_after(&mut stack, elem, is_empty);
                    continue;
                };
                let version = match attrs.version.as_deref() {
                    Some(v) => match parse_number::<u8>(v) {
                        Some(v) => v,
                        None => {
                            continue_after(&mut stack, elem, is_empty);
                            continue;
                        }
                    },
                    None => 0,
                };
                if raw_events.len() >= MAX_EVENTS {
                    return Err(ManifestError::TooLarge("event count"));
                }
                raw_events.push(RawEvent {
                    value,
                    version,
                    name: attrs.symbol.or(attrs.task).unwrap_or_default(),
                    template: attrs.template,
                });
            }

            Elem::Template if in_matching_provider && parent == Some(Elem::Templates) => {
                let attrs = read_attrs(e, &reader)?;
                let tid = attrs.tid.unwrap_or_default();
                if is_empty {
                    templates.entry(tid).or_default();
                } else {
                    current_template = Some((tid, Vec::new()));
                }
            }

            Elem::Struct | Elem::Other if parent == Some(Elem::Template) => {
                if let Some((_, items)) = current_template.as_mut() {
                    let is_data = e.local_name().as_ref() == b"data";
                    if is_data || elem == Elem::Struct {
                        if items.len() >= MAX_FIELDS_PER_TEMPLATE {
                            return Err(ManifestError::TooLarge("template field count"));
                        }
                        let attrs = read_attrs(e, &reader)?;
                        let name = attrs.name.unwrap_or_default();
                        items.push(if is_data {
                            TemplateItem::Data {
                                name,
                                in_type: attrs.in_type.unwrap_or_default(),
                                length: attrs.length,
                                count: attrs.count,
                            }
                        } else {
                            TemplateItem::Struct { name }
                        });
                    }
                }
            }

            _ => {}
        }

        continue_after(&mut stack, elem, is_empty);
    }

    let Some(name) = provider_name else {
        return Err(ManifestError::NoMatchingProvider);
    };

    // Resolve each template once; events referencing it share the result.
    // Re-resolving per event would let a small manifest (one wide template
    // referenced by many events) expand to gigabytes.
    let mut resolved: HashMap<&str, Arc<[FieldDef]>> = HashMap::with_capacity(templates.len());
    let empty: Arc<[FieldDef]> = Arc::from(Vec::new());

    let mut events: HashMap<(u16, u8), EventDef, XxBuildHasher> = HashMap::default();
    for raw in raw_events {
        let key = (raw.value, raw.version);
        if events.contains_key(&key) {
            continue;
        }

        let fields = match raw.template.as_deref() {
            // Parameterless EventSource events carry no `template` attribute.
            None => Arc::clone(&empty),
            Some(tid) => match templates.get_key_value(tid) {
                Some((tid, items)) => Arc::clone(
                    resolved
                        .entry(tid.as_str())
                        .or_insert_with(|| Arc::from(resolve_fields(items))),
                ),
                // Dangling template reference: skip only this event.
                None => continue,
            },
        };

        events.insert(key, EventDef { name: raw.name, fields });
    }

    Ok(ProviderManifest { name, events })
}

/// Pushes `elem` onto the open-element stack unless it was self-closing.
fn continue_after(stack: &mut Vec<Elem>, elem: Elem, is_empty: bool) {
    if !is_empty {
        stack.push(elem);
    }
}

/// Builds a schema-stable [`EventFormat`] for an event definition, using the
/// same offset conventions as the TDH property walker: absolute offsets until
/// the first variable-length field, then `0` (resolved lazily by the
/// framework's skip chain).
pub(crate) fn build_format(fields: &[FieldDef], is_32bit: bool) -> EventFormat {
    let mut format = EventFormat::new();
    let mut running_offset = 0usize;
    let mut seen_variable = false;

    for field in fields {
        let offset = if seen_variable { 0 } else { running_offset };

        let (type_name, location, size) = match field.kind {
            FieldKind::InType(in_type) => intype_to_field_info(in_type, is_32bit),
            FieldKind::Blob32 => ("binary", LocationType::StaticLenPrefix32Array, 0),
            FieldKind::FixedBinary(n) => ("binary", LocationType::Static, n),
            FieldKind::Unsupported => ("unsupported", LocationType::Static, 0),
        };

        format.add_field(EventField::new(
            field.name.clone(), type_name.to_string(), location, offset, size));

        if size == 0 {
            seen_variable = true;
        } else if !seen_variable {
            running_offset += size;
        }
    }

    format
}

#[cfg(test)]
pub(crate) const TEST_MANIFEST: &str =
    include_str!("../../../test_assets/eventsource/one_collect_test_eventsource.xml");

/// GUID of the provider in [`TEST_MANIFEST`] (name hash of
/// `OneCollect-Test-InbandManifest`).
#[cfg(test)]
pub(crate) const TEST_PROVIDER: Guid = Guid::from_u128(0x369e340b_d54c_5d95_1211_b7a318f16882);

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str, in_type: &str) -> FieldDef {
        FieldDef { name: name.into(), kind: FieldKind::InType(map_in_type(in_type).unwrap()) }
    }

    fn parse_test_manifest() -> ProviderManifest {
        parse(TEST_MANIFEST.as_bytes(), &TEST_PROVIDER).expect("fixture parses")
    }

    #[test]
    fn test_provider_guid_matches_name_hash() {
        assert!(TEST_PROVIDER == crate::guid_from_provider_name("OneCollect-Test-InbandManifest"));
    }

    #[test]
    fn parses_provider_identity_and_event_count() {
        let m = parse_test_manifest();
        assert_eq!(m.name, "OneCollect-Test-InbandManifest");
        assert_eq!(m.events.len(), 9);
    }

    #[test]
    fn parses_all_scalar_types() {
        let m = parse_test_manifest();
        let ev = &m.events[&(1, 0)];
        assert_eq!(ev.name, "AllScalars");
        assert_eq!(*ev.fields, vec![
            data("s8", "win:Int8"),
            data("u8", "win:UInt8"),
            data("s16", "win:Int16"),
            data("u16", "win:UInt16"),
            data("s32", "win:Int32"),
            data("u32", "win:UInt32"),
            data("s64", "win:Int64"),
            data("u64", "win:UInt64"),
            data("f32", "win:Float"),
            data("f64", "win:Double"),
            data("b", "win:Boolean"),
            data("c", "win:UInt16"),
        ]);
    }

    #[test]
    fn fuses_byte_array_length_and_blob() {
        let m = parse_test_manifest();
        let ev = &m.events[&(4, 0)];
        assert_eq!(*ev.fields, vec![
            data("before", "win:Int32"),
            FieldDef { name: "data".into(), kind: FieldKind::Blob32 },
            data("after", "win:Int32"),
        ]);
    }

    #[test]
    fn parameterless_event_has_empty_fields() {
        let m = parse_test_manifest();
        let ev = &m.events[&(5, 0)];
        assert_eq!(ev.name, "Ping");
        assert!(ev.fields.is_empty());
    }

    #[test]
    fn start_stop_use_symbol_and_versions_are_keyed() {
        let m = parse_test_manifest();
        assert_eq!(m.events[&(6, 0)].name, "RequestStart");
        assert_eq!(m.events[&(7, 0)].name, "RequestStop");
        assert_eq!(m.events[&(8, 2)].name, "Versioned");
        assert!(!m.events.contains_key(&(8, 0)));
    }

    #[test]
    fn enum_with_map_stays_raw_integer() {
        let m = parse_test_manifest();
        let ev = &m.events[&(3, 0)];
        assert_eq!(*ev.fields, vec![
            data("g", "win:GUID"),
            data("when", "win:FILETIME"),
            data("ptr", "win:Pointer"),
            data("color", "win:UInt32"),
        ]);
    }

    #[test]
    fn rejects_mismatched_provider_guid() {
        let other = Guid::from_u128(1);
        assert_eq!(
            parse(TEST_MANIFEST.as_bytes(), &other).err(),
            Some(ManifestError::NoMatchingProvider)
        );
    }

    #[test]
    fn rejects_malformed_xml_and_non_utf8() {
        let truncated = &TEST_MANIFEST.as_bytes()[..TEST_MANIFEST.len() / 2];
        let mismatched = TEST_MANIFEST.replace("</templates>", "</templatez>");
        assert!(matches!(parse(truncated, &TEST_PROVIDER), Err(ManifestError::Xml(_))));
        assert!(matches!(parse(mismatched.as_bytes(), &TEST_PROVIDER), Err(ManifestError::Xml(_))));
        assert_eq!(parse(&[0xFF, 0xFE, 0x00], &TEST_PROVIDER).err(), Some(ManifestError::NotUtf8));
    }

    #[test]
    fn element_order_and_semantic_errors() {
        // Templates before events, a dangling template reference, an event
        // with an unparseable value, a struct, an array, an unknown inType,
        // a fixed-size binary, and a non-adjacent length reference.
        let xml = r#"<instrumentationManifest><instrumentation><events>
<provider name="P" guid="{00000000-0000-0000-0000-000000000042}">
 <templates>
  <template tid="T1">
   <data name="n" inType="win:UInt32"/>
   <data name="fixed" inType="win:Binary" length="16"/>
   <data name="arr" inType="win:Int32" count="n"/>
  </template>
  <template tid="T2">
   <struct name="s"><data name="inner" inType="win:Int8"/></struct>
   <data name="weird" inType="win:Fancy"/>
   <data name="len" inType="win:UInt32"/>
   <data name="x" inType="win:UInt8"/>
   <data name="blob" inType="win:Binary" length="len"/>
  </template>
  <template tid="Empty"/>
 </templates>
 <events>
  <event value="1" symbol="One" template="T1"/>
  <event value="2" task="TwoTask" template="T2"/>
  <event value="3" symbol="Dangling" template="Missing"/>
  <event value="bogus" symbol="Bad"/>
  <event value="0x10" version="0x1" symbol="Hex" template="Empty"/>
 </events>
</provider>
</events></instrumentation></instrumentationManifest>"#;

        let m = parse(xml.as_bytes(), &Guid::from_u128(0x42)).unwrap();
        assert_eq!(m.name, "P");
        assert_eq!(m.events.len(), 3);

        assert_eq!(*m.events[&(1, 0)].fields, vec![
            data("n", "win:UInt32"),
            FieldDef { name: "fixed".into(), kind: FieldKind::FixedBinary(16) },
            FieldDef { name: "arr".into(), kind: FieldKind::Unsupported },
        ]);

        let two = &m.events[&(2, 0)];
        assert_eq!(two.name, "TwoTask");
        assert_eq!(*two.fields, vec![
            FieldDef { name: "s".into(), kind: FieldKind::Unsupported },
            FieldDef { name: "weird".into(), kind: FieldKind::Unsupported },
            data("len", "win:UInt32"),
            data("x", "win:UInt8"),
            FieldDef { name: "blob".into(), kind: FieldKind::Unsupported },
        ]);

        assert_eq!(m.events[&(16, 1)].name, "Hex");
        assert!(m.events[&(16, 1)].fields.is_empty());
    }

    #[test]
    fn only_the_matching_provider_is_collected() {
        let xml = r#"<events>
<provider name="Other" guid="{00000000-0000-0000-0000-000000000001}">
 <events><event value="1" symbol="FromOther"/></events>
</provider>
<provider name="Mine" guid="{00000000-0000-0000-0000-000000000002}">
 <events><event value="1" symbol="FromMine"/></events>
</provider>
</events>"#;
        let m = parse(xml.as_bytes(), &Guid::from_u128(2)).unwrap();
        assert_eq!(m.name, "Mine");
        assert_eq!(m.events[&(1, 0)].name, "FromMine");
    }

    #[test]
    fn templates_are_resolved_once_and_shared() {
        // One wide template referenced by many events must not be copied per
        // event (memory amplification from a small hostile manifest).
        let data: String = (0..64)
            .map(|i| format!(r#"<data name="f{i}" inType="win:Int32"/>"#))
            .collect();
        let events: String = (1..=500)
            .map(|i| format!(r#"<event value="{i}" symbol="E{i}" template="T"/>"#))
            .collect();
        let xml = format!(
            r#"<provider name="P" guid="{{00000000-0000-0000-0000-000000000002}}">
<events>{events}</events><templates><template tid="T">{data}</template></templates>
</provider>"#);

        let m = parse(xml.as_bytes(), &Guid::from_u128(2)).unwrap();
        assert_eq!(m.events.len(), 500);
        let first = &m.events[&(1, 0)].fields;
        assert_eq!(first.len(), 64);
        assert!(m.events.values().all(|e| Arc::ptr_eq(&e.fields, first)));
    }

    #[test]
    fn limits_reject_oversized_names() {
        let long = "x".repeat(MAX_NAME_LEN + 1);
        let xml = format!(
            r#"<provider name="{long}" guid="{{00000000-0000-0000-0000-000000000002}}"/>"#);
        assert_eq!(
            parse(xml.as_bytes(), &Guid::from_u128(2)).err(),
            Some(ManifestError::TooLarge("attribute value length"))
        );
    }

    #[test]
    fn parse_guid_variants() {
        let g = Guid::from_u128(0x369e340b_d54c_5d95_1211_b7a318f16882);
        assert!(parse_guid("{369e340b-d54c-5d95-1211-b7a318f16882}") == Some(g));
        assert!(parse_guid("369E340B-D54C-5D95-1211-B7A318F16882") == Some(g));
        assert!(parse_guid("{369e340b-d54c-5d95-1211}").is_none());
        assert!(parse_guid("{369e340b-d54c-5d95-1211-b7a318f1688z}").is_none());
    }

    #[test]
    fn build_format_offsets_and_pointer_width() {
        let m = parse_test_manifest();

        // Misc: guid(16) filetime(8) pointer(4|8) u32(4)
        let f64b = build_format(&m.events[&(3, 0)].fields, false);
        let offsets: Vec<(usize, usize)> = f64b.fields().iter().map(|f| (f.offset, f.size)).collect();
        assert_eq!(offsets, vec![(0, 16), (16, 8), (24, 8), (32, 4)]);

        let f32b = build_format(&m.events[&(3, 0)].fields, true);
        let offsets: Vec<(usize, usize)> = f32b.fields().iter().map(|f| (f.offset, f.size)).collect();
        assert_eq!(offsets, vec![(0, 16), (16, 8), (24, 4), (28, 4)]);

        // Blob: s32 at 0, blob32 at 4 (variable), s32 lazily resolved.
        let blob = build_format(&m.events[&(4, 0)].fields, false);
        let fields = blob.fields();
        assert_eq!(fields[1].location, LocationType::StaticLenPrefix32Array);
        assert_eq!(fields[1].type_name, "binary");
        assert_eq!((fields[1].offset, fields[1].size), (4, 0));
        assert_eq!((fields[2].offset, fields[2].size), (0, 4));

        // Boolean is a 4-byte BOOL.
        let scalars = build_format(&m.events[&(1, 0)].fields, false);
        let b = scalars.fields().iter().find(|f| f.name == "b").unwrap();
        assert_eq!(b.size, 4);
    }
}
