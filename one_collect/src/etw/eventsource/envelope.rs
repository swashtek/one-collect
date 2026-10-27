// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parsing and validation of the 8-byte `ManifestEnvelope` that prefixes every
//! EventSource in-band manifest chunk.
//!
//! Layout (from `System.Diagnostics.Tracing.ManifestEnvelope`):
//!
//! ```text
//! offset 0  u8   Format        (1 = SimpleXmlFormat)
//! offset 1  u8   MajorVersion  (1)
//! offset 2  u8   MinorVersion  (0; any value accepted for forward compatibility)
//! offset 3  u8   Magic         (0x5B)
//! offset 4  u16  TotalChunks   (little-endian, > 0)
//! offset 6  u16  ChunkNumber   (little-endian, < TotalChunks)
//! offset 8  ...  UTF-8 manifest bytes for this chunk (non-empty)
//! ```

/// Size of the envelope that precedes each chunk's manifest bytes.
pub(crate) const ENVELOPE_SIZE: usize = 8;

const FORMAT_SIMPLE_XML: u8 = 1;
const MAJOR_VERSION: u8 = 1;
const MAGIC: u8 = 0x5B;

/// A validated manifest envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManifestEnvelope {
    pub(crate) format: u8,
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) total_chunks: u16,
    pub(crate) chunk_number: u16,
}

impl ManifestEnvelope {
    /// Returns `true` if `other` describes the same emission header (format,
    /// versions, and total chunk count). Used to reject chunks that cannot
    /// belong to the anchored emission.
    pub(crate) fn same_header(&self, other: &Self) -> bool {
        self.format == other.format
            && self.major == other.major
            && self.minor == other.minor
            && self.total_chunks == other.total_chunks
    }
}

/// Why an envelope was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeError {
    /// Payload is not larger than the envelope (no manifest bytes).
    TooShort,
    BadMagic,
    UnsupportedFormat,
    UnsupportedMajorVersion,
    /// `TotalChunks == 0` or `ChunkNumber >= TotalChunks`.
    ChunkOutOfRange,
}

/// Parses and validates the envelope, returning it with the chunk bytes.
pub(crate) fn parse(user_data: &[u8]) -> Result<(ManifestEnvelope, &[u8]), EnvelopeError> {
    if user_data.len() <= ENVELOPE_SIZE {
        return Err(EnvelopeError::TooShort);
    }

    let envelope = ManifestEnvelope {
        format: user_data[0],
        major: user_data[1],
        minor: user_data[2],
        total_chunks: u16::from_le_bytes([user_data[4], user_data[5]]),
        chunk_number: u16::from_le_bytes([user_data[6], user_data[7]]),
    };

    if user_data[3] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    if envelope.format != FORMAT_SIMPLE_XML {
        return Err(EnvelopeError::UnsupportedFormat);
    }
    if envelope.major != MAJOR_VERSION {
        return Err(EnvelopeError::UnsupportedMajorVersion);
    }
    if envelope.total_chunks == 0 || envelope.chunk_number >= envelope.total_chunks {
        return Err(EnvelopeError::ChunkOutOfRange);
    }

    Ok((envelope, &user_data[ENVELOPE_SIZE..]))
}

/// Builds an envelope + chunk payload.  Test helper shared by the
/// `eventsource` and `tdh` unit tests.
#[cfg(test)]
pub(crate) fn build_chunk(total_chunks: u16, chunk_number: u16, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![FORMAT_SIMPLE_XML, MAJOR_VERSION, 0, MAGIC];
    out.extend_from_slice(&total_chunks.to_le_bytes());
    out.extend_from_slice(&chunk_number.to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_envelope() {
        let data = build_chunk(3, 1, b"<x/>");
        let (env, chunk) = parse(&data).unwrap();
        assert_eq!(env, ManifestEnvelope {
            format: 1, major: 1, minor: 0, total_chunks: 3, chunk_number: 1,
        });
        assert_eq!(chunk, b"<x/>");
    }

    #[test]
    fn accepts_any_minor_version() {
        let mut data = build_chunk(1, 0, b"a");
        data[2] = 7;
        assert_eq!(parse(&data).unwrap().0.minor, 7);
    }

    #[test]
    fn rejects_invalid_envelopes() {
        let ok = build_chunk(2, 0, b"a");

        assert_eq!(parse(&ok[..ENVELOPE_SIZE]), Err(EnvelopeError::TooShort));
        assert_eq!(parse(&[]), Err(EnvelopeError::TooShort));

        let mut bad = ok.clone();
        bad[3] = 0x5C;
        assert_eq!(parse(&bad), Err(EnvelopeError::BadMagic));

        let mut bad = ok.clone();
        bad[0] = 2;
        assert_eq!(parse(&bad), Err(EnvelopeError::UnsupportedFormat));

        let mut bad = ok.clone();
        bad[1] = 2;
        assert_eq!(parse(&bad), Err(EnvelopeError::UnsupportedMajorVersion));

        assert_eq!(parse(&build_chunk(0, 0, b"a")), Err(EnvelopeError::ChunkOutOfRange));
        assert_eq!(parse(&build_chunk(2, 2, b"a")), Err(EnvelopeError::ChunkOutOfRange));
    }
}
