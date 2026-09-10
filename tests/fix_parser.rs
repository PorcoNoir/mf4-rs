//! Regression tests for parser robustness fixes: malformed or truncated
//! files must produce `Err(MdfError)` — never a panic — and several decode
//! bugs (float bit_offset, interior-NUL strings, bit_count == 0, VLSD short
//! payloads) must be handled correctly.

use mf4_rs::blocks::channel_block::ChannelBlock;
use mf4_rs::blocks::channel_group_block::ChannelGroupBlock;
use mf4_rs::blocks::common::{read_string_block, BlockParse, DataType};
use mf4_rs::blocks::data_block::DataBlock;
use mf4_rs::blocks::data_group_block::DataGroupBlock;
use mf4_rs::blocks::data_list_block::DataListBlock;
use mf4_rs::blocks::header_block::HeaderBlock;
use mf4_rs::blocks::identification_block::IdentificationBlock;
use mf4_rs::blocks::source_block::{read_source_block, SourceBlock};
use mf4_rs::blocks::text_block::TextBlock;
use mf4_rs::error::MdfError;
use mf4_rs::parsing::decoder::{decode_channel_value, DecodedValue};
use mf4_rs::parsing::mdf_file::MdfFile;
use mf4_rs::parsing::raw_channel_group::RawChannelGroup;
use mf4_rs::parsing::raw_data_group::RawDataGroup;

// ---------------------------------------------------------------------------
// Helpers to build synthetic (malformed) MDF byte images
// ---------------------------------------------------------------------------

/// A 24-byte MDF block header.
fn block_header(id: &[u8; 4], block_len: u64, links_nr: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(id);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&block_len.to_le_bytes());
    v.extend_from_slice(&links_nr.to_le_bytes());
    v
}

/// A valid 168-byte file prefix (##ID + ##HD) with the given first_dg_addr.
fn valid_prefix(first_dg_addr: u64) -> Vec<u8> {
    let id = IdentificationBlock::default().to_bytes().unwrap();
    let mut hd = HeaderBlock::default();
    hd.first_dg_addr = first_dg_addr;
    let hd = hd.to_bytes().unwrap();
    let mut file = Vec::new();
    file.extend_from_slice(&id);
    file.extend_from_slice(&hd);
    assert_eq!(file.len(), 168);
    file
}

/// A serialized ##DG block with the given links.
fn dg_block(next_dg_addr: u64, first_cg_addr: u64) -> Vec<u8> {
    let mut dg = DataGroupBlock::default();
    dg.next_dg_addr = next_dg_addr;
    dg.first_cg_addr = first_cg_addr;
    dg.to_bytes().unwrap()
}

// ---------------------------------------------------------------------------
// 1/5. Truncated files must error, never panic
// ---------------------------------------------------------------------------

#[test]
fn truncated_files_error_instead_of_panicking() {
    // 0 bytes, below the 64-byte ##ID, between ##ID and ##HD, one short of
    // the full 168-byte prefix.
    for len in [0usize, 63, 100, 167] {
        let data = vec![0u8; len];
        let result = MdfFile::parse_from_bytes(data);
        assert!(result.is_err(), "file of {} bytes must not parse", len);
    }
    // A truncated but otherwise valid prefix, cut at the same lengths.
    let full = valid_prefix(0);
    for len in [63usize, 100, 167] {
        let result = MdfFile::parse_from_bytes(full[..len].to_vec());
        assert!(result.is_err(), "truncated valid prefix ({} bytes) must not parse", len);
    }
}

#[test]
fn dangling_dg_address_errors() {
    // Valid ##ID + ##HD, but first_dg_addr points far beyond EOF.
    let file = valid_prefix(1_000_000);
    let result = MdfFile::parse_from_bytes(file);
    assert!(matches!(result, Err(MdfError::TooShortBuffer { .. })));
}

#[test]
fn dangling_cg_address_errors() {
    // DG at 168 whose first_cg_addr dangles beyond EOF.
    let mut file = valid_prefix(168);
    file.extend_from_slice(&dg_block(0, 999_999));
    let result = MdfFile::parse_from_bytes(file);
    assert!(matches!(result, Err(MdfError::TooShortBuffer { .. })));
}

// ---------------------------------------------------------------------------
// 6. Cycle detection in linked-list walks
// ---------------------------------------------------------------------------

#[test]
fn cyclic_dg_links_error() {
    // DG at 168 whose next_dg_addr points back to itself.
    let mut file = valid_prefix(168);
    file.extend_from_slice(&dg_block(168, 0));
    let result = MdfFile::parse_from_bytes(file);
    assert!(matches!(result, Err(MdfError::BlockLinkError(_))));
}

#[test]
fn cyclic_two_dg_links_error() {
    // DG at 168 -> DG at 232 -> back to 168.
    let mut file = valid_prefix(168);
    file.extend_from_slice(&dg_block(232, 0));
    file.extend_from_slice(&dg_block(168, 0));
    let result = MdfFile::parse_from_bytes(file);
    assert!(matches!(result, Err(MdfError::BlockLinkError(_))));
}

#[test]
fn cyclic_dt_chain_errors() {
    // A ##DL whose `next` points back to itself must not loop forever.
    // Image layout: 8 bytes padding (so the DL is not at "null" address 0),
    // DL at offset 8 (56 bytes: header + next + 1 data link + flags/nr/len),
    // DT at offset 64.
    let dl_offset = 8u64;
    let dt_addr = 64u64;

    let mut dl = block_header(b"##DL", 56, 2);
    dl.extend_from_slice(&dl_offset.to_le_bytes()); // next -> itself (cycle)
    dl.extend_from_slice(&dt_addr.to_le_bytes()); // data link -> DT
    dl.push(1); // flags: equal length
    dl.extend_from_slice(&[0u8; 3]); // reserved
    dl.extend_from_slice(&1u32.to_le_bytes()); // data_block_nr
    dl.extend_from_slice(&8u64.to_le_bytes()); // data_block_len
    assert_eq!(dl.len(), 56);

    let mut image = vec![0u8; 8];
    image.extend_from_slice(&dl);
    image.extend_from_slice(&block_header(b"##DT", 32, 0));
    image.extend_from_slice(&[0u8; 8]);

    let mut dg = DataGroupBlock::default();
    dg.data_block_addr = dl_offset;
    let raw_dg = RawDataGroup { block: dg, channel_groups: Vec::new() };
    let result = raw_dg.data_blocks(&image);
    assert!(matches!(result, Err(MdfError::BlockLinkError(_))));
}

// ---------------------------------------------------------------------------
// 3. ##DL with links_nr == 0 must error (used to underflow-panic)
// ---------------------------------------------------------------------------

#[test]
fn data_list_zero_links_errors() {
    let mut bytes = block_header(b"##DL", 40, 0);
    bytes.push(0); // flags
    bytes.extend_from_slice(&[0u8; 3]); // reserved
    bytes.extend_from_slice(&0u32.to_le_bytes()); // data_block_nr
    bytes.extend_from_slice(&[0u8; 8]); // padding
    let result = DataListBlock::from_bytes(&bytes);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 4. ##DV blocks parse as data blocks
// ---------------------------------------------------------------------------

#[test]
fn dv_block_parses_as_data_block() {
    let mut bytes = block_header(b"##DV", 32, 0);
    bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let dv = DataBlock::from_bytes(&bytes).expect("##DV must parse");
    assert_eq!(dv.data.as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8]);

    // ##DT still parses, anything else is still rejected.
    let mut dt = block_header(b"##DT", 32, 0);
    dt.extend_from_slice(&[0u8; 8]);
    assert!(DataBlock::from_bytes(&dt).is_ok());
    let mut tx = block_header(b"##TX", 32, 0);
    tx.extend_from_slice(&[0u8; 8]);
    assert!(matches!(DataBlock::from_bytes(&tx), Err(MdfError::BlockIDError { .. })));
}

// ---------------------------------------------------------------------------
// 1. read_string_block bounds checking
// ---------------------------------------------------------------------------

#[test]
fn read_string_block_out_of_range_errors() {
    let bytes = vec![0u8; 32];
    // Address beyond EOF
    assert!(matches!(
        read_string_block(&bytes, 1000),
        Err(MdfError::TooShortBuffer { .. })
    ));
    // Address whose 24-byte header would run past EOF
    assert!(matches!(
        read_string_block(&bytes, 16),
        Err(MdfError::TooShortBuffer { .. })
    ));
    // Empty file data (the conversion path passes &[])
    assert!(matches!(
        read_string_block(&[], 8),
        Err(MdfError::TooShortBuffer { .. })
    ));
    // Address 0 stays "no block"
    assert!(matches!(read_string_block(&bytes, 0), Ok(None)));
}

// ---------------------------------------------------------------------------
// 2. SourceBlock bounds checking (links + off-by-one on data section)
// ---------------------------------------------------------------------------

#[test]
fn source_block_short_buffer_errors() {
    // Header claims 3 links, but the buffer ends before the data section.
    // The old code checked data_start + 2 but indexed data_start + 2 (needs
    // 3 bytes) — a 50-byte buffer used to pass the check and then panic.
    let header = block_header(b"##SI", 56, 3);
    for len in [24usize, 30, 48, 50] {
        let mut bytes = header.clone();
        bytes.resize(len, 0);
        let result = SourceBlock::from_bytes(&bytes);
        assert!(
            matches!(result, Err(MdfError::TooShortBuffer { .. })),
            "SourceBlock with {} bytes must error",
            len
        );
    }
    // 51 bytes (24 + 3*8 + 3) is the minimum that parses.
    let mut ok = header.clone();
    ok.resize(51, 0);
    assert!(SourceBlock::from_bytes(&ok).is_ok());

    // read_source_block with out-of-range address / block_len
    let bytes = vec![0u8; 16];
    assert!(read_source_block(&bytes, 8).is_err());
    let mut mmap = block_header(b"##SI", 1024, 3); // block_len larger than file
    mmap.resize(64, 0);
    assert!(read_source_block(&mmap, 0).is_err());
}

// ---------------------------------------------------------------------------
// 7b. Floats with bit_offset != 0 are shifted before from_bits
// ---------------------------------------------------------------------------

#[test]
fn float_with_bit_offset_is_shifted() {
    let mut ch = ChannelBlock::default();
    ch.data_type = DataType::FloatLE;
    ch.bit_count = 32;
    ch.bit_offset = 4;
    ch.byte_offset = 0;

    let value = 1.5f32;
    let raw = value.to_bits() as u64;
    // Place the 32 float bits 4 bits up inside 5 bytes (LE).
    let shifted = raw << 4;
    let mut record = Vec::new();
    record.extend_from_slice(&shifted.to_le_bytes()[..5]);
    record.extend_from_slice(&[0u8; 3]); // trailing junk in the record

    match decode_channel_value(&record, 0, &ch) {
        Some(DecodedValue::Float(f)) => assert_eq!(f, 1.5),
        other => panic!("expected Float(1.5), got {:?}", other),
    }

    // 64-bit float at bit_offset 4 spans 9 bytes.
    let mut ch64 = ChannelBlock::default();
    ch64.data_type = DataType::FloatLE;
    ch64.bit_count = 64;
    ch64.bit_offset = 4;
    ch64.byte_offset = 0;
    let raw64 = 42.25f64.to_bits() as u128;
    let shifted64 = raw64 << 4;
    let mut record64 = shifted64.to_le_bytes()[..9].to_vec();
    record64.extend_from_slice(&[0u8; 7]);
    match decode_channel_value(&record64, 0, &ch64) {
        Some(DecodedValue::Float(f)) => assert_eq!(f, 42.25),
        other => panic!("expected Float(42.25), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 7d. String decoding stops at the FIRST NUL
// ---------------------------------------------------------------------------

#[test]
fn string_decoding_stops_at_first_nul() {
    let mut ch = ChannelBlock::default();
    ch.data_type = DataType::StringUtf8;
    ch.bit_count = 5 * 8; // 5 bytes: "ON\0FF"
    ch.byte_offset = 0;

    let record = b"ON\0FF";
    match decode_channel_value(record, 0, &ch) {
        Some(DecodedValue::String(s)) => assert_eq!(s, "ON"),
        other => panic!("expected String(\"ON\"), got {:?}", other),
    }

    // Latin1 too
    ch.data_type = DataType::StringLatin1;
    match decode_channel_value(record, 0, &ch) {
        Some(DecodedValue::String(s)) => assert_eq!(s, "ON"),
        other => panic!("expected String(\"ON\"), got {:?}", other),
    }

    // UTF-16LE with an interior NUL code unit and an odd byte count: the
    // trailing byte is dropped instead of refusing to decode.
    let mut ch16 = ChannelBlock::default();
    ch16.data_type = DataType::StringUtf16LE;
    ch16.bit_count = 9 * 8; // 9 bytes (odd)
    ch16.byte_offset = 0;
    let record16: &[u8] = &[b'O', 0, b'N', 0, 0, 0, b'F', 0, b'F'];
    match decode_channel_value(record16, 0, &ch16) {
        Some(DecodedValue::String(s)) => assert_eq!(s, "ON"),
        other => panic!("expected String(\"ON\"), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 8. TextBlock: first-NUL termination, leading NULs are NOT stripped
// ---------------------------------------------------------------------------

#[test]
fn text_block_truncates_at_first_nul_only() {
    // "AB\0CD" + padding: text is "AB", not "AB\0CD" and not "ABCD".
    let mut bytes = block_header(b"##TX", 32, 0);
    bytes.extend_from_slice(b"AB\0CD\0\0\0");
    let tx = TextBlock::from_bytes(&bytes).unwrap();
    assert_eq!(tx.text, "AB");

    // A leading NUL terminates immediately — it must not be trimmed away to
    // reveal a different name.
    let mut bytes = block_header(b"##TX", 32, 0);
    bytes.extend_from_slice(b"\0BAD\0\0\0\0");
    let tx = TextBlock::from_bytes(&bytes).unwrap();
    assert_eq!(tx.text, "");
}

// ---------------------------------------------------------------------------
// 7c. bit_count == 0 on signed channels must not underflow
// ---------------------------------------------------------------------------

#[test]
fn zero_bit_count_signed_returns_none() {
    for data_type in [
        DataType::SignedIntegerLE,
        DataType::SignedIntegerBE,
        DataType::UnsignedIntegerLE,
        DataType::FloatLE,
    ] {
        let mut ch = ChannelBlock::default();
        ch.data_type = data_type.clone();
        ch.bit_count = 0;
        ch.byte_offset = 0;
        let record = [0u8; 8];
        assert_eq!(
            decode_channel_value(&record, 0, &ch),
            None,
            "bit_count == 0 must decode to None for {:?}",
            data_type
        );
    }
}

// ---------------------------------------------------------------------------
// 7a. VLSD short payload decoded as fixed-width numeric returns None
// ---------------------------------------------------------------------------

#[test]
fn vlsd_short_payload_returns_none() {
    let mut ch = ChannelBlock::default();
    ch.channel_type = 1; // VLSD
    ch.data = 0x1000; // non-zero SD pointer
    ch.data_type = DataType::UnsignedIntegerLE;
    ch.bit_count = 64;

    // Payload shorter than the 8 bytes a u64 read needs.
    let payload = [1u8, 2, 3];
    assert_eq!(decode_channel_value(&payload, 0, &ch), None);

    // Same for floats.
    ch.data_type = DataType::FloatLE;
    ch.bit_count = 32;
    let payload = [9u8];
    assert_eq!(decode_channel_value(&payload, 0, &ch), None);

    // A long-enough VLSD payload still decodes.
    ch.data_type = DataType::UnsignedIntegerLE;
    ch.bit_count = 16;
    let payload = 513u16.to_le_bytes();
    assert_eq!(
        decode_channel_value(&payload, 0, &ch),
        Some(DecodedValue::UnsignedInteger(513))
    );
}

// ---------------------------------------------------------------------------
// 10. Unsorted data groups are refused loudly on data access
// ---------------------------------------------------------------------------

#[test]
fn unsorted_data_group_data_access_errors() {
    let mut dg = DataGroupBlock::default();
    dg.record_id_len = 1;
    dg.data_block_addr = 0;
    let cg = |record_id: u64| {
        let mut block = ChannelGroupBlock::default();
        block.record_id = record_id;
        block.samples_byte_nr = 4;
        RawChannelGroup { block, raw_channels: Vec::new() }
    };
    let raw_dg = RawDataGroup {
        block: dg,
        channel_groups: vec![cg(1), cg(2)],
    };
    let result = raw_dg.data_blocks(&[]);
    assert!(
        matches!(result, Err(MdfError::BlockSerializationError(_))),
        "unsorted data group must refuse data access, got {:?}",
        result.map(|v| v.len())
    );

    // A single-CG group with record_id_len > 0 keeps working.
    let mut dg = DataGroupBlock::default();
    dg.record_id_len = 1;
    dg.data_block_addr = 0; // no data: empty result, but no error
    let raw_dg = RawDataGroup { block: dg, channel_groups: vec![cg(1)] };
    assert!(raw_dg.data_blocks(&[]).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 11. IOError Display includes the underlying error
// ---------------------------------------------------------------------------

#[test]
fn io_error_display_includes_cause() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing.mf4 not found");
    let err = MdfError::from(io);
    let msg = err.to_string();
    assert!(
        msg.contains("missing.mf4 not found"),
        "IOError Display must include the underlying error, got: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Identification block: non-UTF8 identifier errors instead of panicking
// ---------------------------------------------------------------------------

#[test]
fn non_utf8_identifier_errors() {
    let mut bytes = vec![0xFFu8; 64];
    bytes[28..30].copy_from_slice(&410u16.to_le_bytes());
    let result = IdentificationBlock::from_bytes(&bytes);
    assert!(matches!(result, Err(MdfError::FileIdentifierError(_))));
}
