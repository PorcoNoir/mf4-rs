use std::collections::HashMap;

use byteorder::{ByteOrder, BigEndian, LittleEndian};

use crate::cut::clone_block_to_writer;
use crate::error::MdfError;
use crate::writer::MdfWriter;
use crate::parsing::mdf_file::MdfFile;
use crate::parsing::decoder::{decode_channel_value, DecodedValue};
use crate::blocks::common::{BlockHeader, BlockParse, DataType, read_string_block};
use crate::blocks::conversion::ConversionBlock;

#[derive(Debug, Clone)]
struct ChannelMeta {
    name: Option<String>,
    data_type: DataType,
    bit_offset: u8,
    byte_offset: u32,
    bit_count: u32,
    channel_type: u8,
    sync_type: u8,
    /// Whether the source channel was VLSD (channel_type == 1 && data != 0).
    /// The raw `data` address differs between source files, so equality is
    /// reduced to a boolean.
    is_vlsd: bool,
    /// Structural fingerprint of the conversion chain (type, coefficients and
    /// referenced text contents, recursively). Two channels only match when
    /// their conversions are equivalent — otherwise physically incompatible
    /// raw streams would be concatenated under one scaling.
    conv_fingerprint: Vec<u8>,
    unit: Option<String>,
    // Source-file link addresses, cloned into the output on write.
    conversion_addr: u64,
    unit_addr: u64,
    comment_addr: u64,
    source_addr: u64,
}

impl ChannelMeta {
    fn matches(&self, other: &Self) -> bool {
        self.name == other.name
            && self.data_type == other.data_type
            && self.bit_offset == other.bit_offset
            && self.byte_offset == other.byte_offset
            && self.bit_count == other.bit_count
            && self.channel_type == other.channel_type
            && self.sync_type == other.sync_type
            && self.is_vlsd == other.is_vlsd
            && self.conv_fingerprint == other.conv_fingerprint
            && self.unit == other.unit
    }
}

#[derive(Debug, Clone)]
struct GroupMeta {
    record_id_len: u8,
    channels: Vec<ChannelMeta>,
}

impl GroupMeta {
    fn matches(&self, other: &Self) -> bool {
        self.record_id_len == other.record_id_len
            && self.channels.len() == other.channels.len()
            && self.channels.iter().zip(other.channels.iter()).all(|(a, b)| a.matches(b))
    }
}

struct MergedGroup {
    meta: GroupMeta,
    data: Vec<Vec<DecodedValue>>, // per channel
    /// Which input file (0 or 1) supplies the metadata blocks
    /// (conversion/unit/comment/source) cloned into the output.
    src_file: usize,
}

/// Build a structural fingerprint of a conversion chain: conversion type,
/// coefficient bit patterns and the contents of referenced ##TX/##MD blocks,
/// followed recursively through cc_ref. Used to decide whether two channels
/// from different files share an equivalent conversion.
fn conv_fingerprint(
    mmap: &[u8],
    addr: u64,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), MdfError> {
    if addr == 0 || depth > 8 {
        out.push(0xFF);
        return Ok(());
    }
    let offset = addr as usize;
    if offset + 24 > mmap.len() {
        return Ok(());
    }
    let header = BlockHeader::from_bytes(&mmap[offset..offset + 24])?;
    let total_len = header.block_len as usize;
    if total_len < 24 || offset + total_len > mmap.len() {
        return Ok(());
    }
    match header.id.as_str() {
        "##TX" | "##MD" => {
            out.push(b'T');
            out.extend_from_slice(&mmap[offset + 24..offset + total_len]);
        }
        "##CC" => {
            let cc = ConversionBlock::from_bytes(&mmap[offset..offset + total_len])?;
            out.push(b'C');
            out.push(cc.cc_type.to_u8());
            for v in &cc.cc_val {
                out.extend_from_slice(&v.to_bits().to_le_bytes());
            }
            for &r in &cc.cc_ref {
                conv_fingerprint(mmap, r, out, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn vlsd_payload_to_value(bytes: &[u8], data_type: &DataType) -> DecodedValue {
    match data_type {
        DataType::StringUtf8 => match std::str::from_utf8(bytes) {
            Ok(s) => DecodedValue::String(s.trim_end_matches('\0').to_string()),
            Err(_) => DecodedValue::String(String::from("<Invalid UTF8>")),
        },
        DataType::StringLatin1 => {
            let s: String = bytes.iter().map(|&b| b as char).collect();
            DecodedValue::String(s.trim_end_matches('\0').to_string())
        }
        DataType::StringUtf16LE => {
            if bytes.len() % 2 != 0 {
                return DecodedValue::String(String::from("<Invalid UTF16LE>"));
            }
            let u16_data: Vec<u16> = bytes.chunks_exact(2).map(LittleEndian::read_u16).collect();
            match String::from_utf16(&u16_data) {
                Ok(s) => DecodedValue::String(s.trim_end_matches('\0').to_string()),
                Err(_) => DecodedValue::String(String::from("<Invalid UTF16LE>")),
            }
        }
        DataType::StringUtf16BE => {
            if bytes.len() % 2 != 0 {
                return DecodedValue::String(String::from("<Invalid UTF16BE>"));
            }
            let u16_data: Vec<u16> = bytes.chunks_exact(2).map(BigEndian::read_u16).collect();
            match String::from_utf16(&u16_data) {
                Ok(s) => DecodedValue::String(s.trim_end_matches('\0').to_string()),
                Err(_) => DecodedValue::String(String::from("<Invalid UTF16BE>")),
            }
        }
        DataType::MimeSample => DecodedValue::MimeSample(bytes.to_vec()),
        DataType::MimeStream => DecodedValue::MimeStream(bytes.to_vec()),
        _ => DecodedValue::ByteArray(bytes.to_vec()),
    }
}

fn collect_groups(file: &MdfFile, src_file: usize) -> Result<Vec<MergedGroup>, MdfError> {
    let mut groups = Vec::new();
    let mmap = &file.mmap;
    for dg in &file.data_groups {
        let record_id_len = dg.block.record_id_len;
        for cg in &dg.channel_groups {
            if cg.block.invalidation_bytes_nr > 0 {
                return Err(MdfError::BlockSerializationError(
                    "merge: channel groups with invalidation bytes are not supported \
                     (per-sample validity would be silently dropped)"
                        .into(),
                ));
            }
            let mut metas = Vec::new();
            for ch in &cg.raw_channels {
                let name = read_string_block(mmap, ch.block.name_addr)?;
                let unit = read_string_block(mmap, ch.block.unit_addr)?;
                let mut fp = Vec::new();
                conv_fingerprint(mmap, ch.block.conversion_addr, &mut fp, 0)?;
                metas.push(ChannelMeta {
                    name,
                    data_type: ch.block.data_type.clone(),
                    bit_offset: ch.block.bit_offset,
                    byte_offset: ch.block.byte_offset,
                    bit_count: ch.block.bit_count,
                    channel_type: ch.block.channel_type,
                    sync_type: ch.block.sync_type,
                    is_vlsd: ch.block.channel_type == 1 && ch.block.data != 0,
                    conv_fingerprint: fp,
                    unit,
                    conversion_addr: ch.block.conversion_addr,
                    unit_addr: ch.block.unit_addr,
                    comment_addr: ch.block.comment_addr,
                    source_addr: ch.block.source_addr,
                });
            }
            let mut data: Vec<Vec<DecodedValue>> = metas.iter().map(|_| Vec::new()).collect();
            for (idx, ch) in cg.raw_channels.iter().enumerate() {
                let is_vlsd = ch.block.channel_type == 1 && ch.block.data != 0;
                let mut iter = ch.records(dg, cg, mmap)?;
                while let Some(rec) = iter.next() {
                    let bytes = rec?;
                    let val = if is_vlsd {
                        vlsd_payload_to_value(bytes.as_ref(), &ch.block.data_type)
                    } else {
                        decode_channel_value(bytes.as_ref(), record_id_len as usize, &ch.block)
                            .unwrap_or(DecodedValue::Unknown)
                    };
                    data[idx].push(val);
                }
            }
            groups.push(MergedGroup {
                meta: GroupMeta { record_id_len, channels: metas },
                data,
                src_file,
            });
        }
    }
    Ok(groups)
}


/// Merge two MDF files into a new file.
///
/// Channel groups that share the same layout — channel names, data types,
/// offsets, bit counts, channel/sync types, **units and conversions** — are
/// concatenated; groups that do not match are appended as separate groups.
/// Conversion, unit, comment and source blocks are cloned recursively into
/// the output, so merged channels keep their physical scaling and metadata.
///
/// Master/time channel values are concatenated verbatim (no re-basing of the
/// second file's time axis); the output's header start time is taken from
/// `first`. Files using invalidation bits are rejected.
///
/// # Arguments
/// * `output` - Path for the merged file
/// * `first` - Path to the first input file
/// * `second` - Path to the second input file
///
/// # Returns
/// `Ok(())` on success or an [`MdfError`] otherwise.
pub fn merge_files(output: &str, first: &str, second: &str) -> Result<(), MdfError> {
    let mdf1 = MdfFile::parse_from_file(first)?;
    let mdf2 = MdfFile::parse_from_file(second)?;

    let mut groups = collect_groups(&mdf1, 0)?;
    let other_groups = collect_groups(&mdf2, 1)?;

    for og in other_groups {
        if let Some(g1) = groups.iter_mut().find(|g| g.meta.matches(&og.meta)) {
            for (vals1, vals2) in g1.data.iter_mut().zip(og.data.into_iter()) {
                vals1.extend(vals2);
            }
        } else {
            groups.push(og);
        }
    }

    let mut writer = MdfWriter::new(output)?;
    writer.init_mdf_file()?;
    writer.set_start_time(
        mdf1.header.abs_time,
        mdf1.header.tz_offset,
        mdf1.header.daylight_save_time,
        mdf1.header.time_flags,
        mdf1.header.time_quality,
    )?;

    let mmaps: [&[u8]; 2] = [&mdf1.mmap, &mdf2.mmap];
    // One clone-cache per source file: block addresses are only unique within
    // a single input file.
    let mut caches: [HashMap<u64, u64>; 2] = [HashMap::new(), HashMap::new()];

    for group in groups {
        let cg_id = writer.add_channel_group(None, |_| {})?;
        let src_mmap = mmaps[group.src_file];
        let cache = &mut caches[group.src_file];
        let mut last_cn: Option<String> = None;
        for ch in &group.meta.channels {
            // Offsets are copied from the source layout; a channel at byte 0
            // that is not first in the list must keep its offset.
            let id = writer.add_channel_preserving_offsets(&cg_id, last_cn.as_deref(), |cn| {
                cn.data_type = ch.data_type.clone();
                if let Some(n) = &ch.name {
                    cn.name = Some(n.clone());
                }
                cn.sync_type = ch.sync_type;
                if ch.is_vlsd {
                    cn.channel_type = 1;
                    // Non-zero placeholder so `start_data_block` recognises this
                    // channel as VLSD; `finish_data_block` will overwrite the
                    // link with the real ##SD address.
                    cn.data = 1;
                    cn.bit_offset = 0;
                    cn.byte_offset = ch.byte_offset;
                    cn.bit_count = 64;
                } else {
                    cn.channel_type = ch.channel_type;
                    cn.bit_offset = ch.bit_offset;
                    cn.byte_offset = ch.byte_offset;
                    cn.bit_count = ch.bit_count;
                }
            })?;

            // Clone conversion/unit/comment/source blocks from the source
            // file and patch the channel's links (CN link offsets: source 48,
            // conversion 56, unit 72, comment 80 — same as cut).
            let cn_pos = writer.get_block_position(&id).ok_or_else(|| {
                MdfError::BlockLinkError(format!("cn '{}' not found", id))
            })?;
            let new_source = clone_block_to_writer(&mut writer, src_mmap, ch.source_addr, cache)?;
            if new_source != 0 {
                writer.update_link(cn_pos + 48, new_source)?;
            }
            let new_conv =
                clone_block_to_writer(&mut writer, src_mmap, ch.conversion_addr, cache)?;
            if new_conv != 0 {
                writer.update_link(cn_pos + 56, new_conv)?;
            }
            let new_unit = clone_block_to_writer(&mut writer, src_mmap, ch.unit_addr, cache)?;
            if new_unit != 0 {
                writer.update_link(cn_pos + 72, new_unit)?;
            }
            let new_comment = clone_block_to_writer(&mut writer, src_mmap, ch.comment_addr, cache)?;
            if new_comment != 0 {
                writer.update_link(cn_pos + 80, new_comment)?;
            }
            last_cn = Some(id);
        }
        writer.start_data_block_for_cg(&cg_id, group.meta.record_id_len)?;
        let record_count = group.data.get(0).map(|v| v.len()).unwrap_or(0);
        for i in 0..record_count {
            let mut vals = Vec::new();
            for (ci, ch_data) in group.data.iter().enumerate() {
                let v = ch_data.get(i).cloned().ok_or_else(|| {
                    MdfError::BlockSerializationError(format!(
                        "merge: channel {} has {} values but the group has {} records",
                        ci,
                        ch_data.len(),
                        record_count
                    ))
                })?;
                vals.push(v);
            }
            writer.write_record(&cg_id, &vals)?;
        }
        writer.finish_data_block(&cg_id)?;
    }

    writer.finalize()
}
