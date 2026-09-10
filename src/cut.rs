use std::collections::HashMap;

use crate::blocks::common::{BlockHeader, BlockParse};
use crate::blocks::conversion::ConversionBlock;
use crate::blocks::source_block::SourceBlock;
use crate::error::MdfError;
use crate::parsing::decoder::{decode_channel_value, DecodedValue};
use crate::parsing::mdf_file::MdfFile;
use crate::writer::MdfWriter;

/// Recursively copy a referenced block (`##TX`, `##MD`, `##SI`, or `##CC`)
/// from the source MDF mmap into the writer, rewriting any link fields so
/// the new block points at freshly written copies of its dependencies.
///
/// Returns the file offset of the new block, or `Ok(0)` when `src_addr` is
/// `0`, the offset is out of range, or the block type is not one of the
/// handled kinds. Already-cloned source addresses are deduplicated through
/// `cache`.
pub(crate) fn clone_block_to_writer(
    writer: &mut MdfWriter,
    mmap: &[u8],
    src_addr: u64,
    cache: &mut HashMap<u64, u64>,
) -> Result<u64, MdfError> {
    if src_addr == 0 {
        return Ok(0);
    }
    if let Some(&dst) = cache.get(&src_addr) {
        return Ok(dst);
    }
    let offset = src_addr as usize;
    if offset + 24 > mmap.len() {
        return Ok(0);
    }
    let header = BlockHeader::from_bytes(&mmap[offset..offset + 24])?;
    let total_len = header.block_len as usize;
    if total_len < 24 || offset + total_len > mmap.len() {
        return Ok(0);
    }

    let dst = match header.id.as_str() {
        "##TX" | "##MD" => {
            // Leaf blocks with no outgoing links: copy raw bytes verbatim.
            writer.write_block(&mmap[offset..offset + total_len])?
        }
        "##SI" => {
            let src_block = SourceBlock::from_bytes(&mmap[offset..offset + total_len])?;
            // Reserve the cache slot before recursing to break cycles.
            cache.insert(src_addr, 0);
            let new_name = clone_block_to_writer(writer, mmap, src_block.name_addr, cache)?;
            let new_path = clone_block_to_writer(writer, mmap, src_block.path_addr, cache)?;
            let new_comment =
                clone_block_to_writer(writer, mmap, src_block.comment_addr, cache)?;
            // SourceBlock has no `to_bytes`, so patch the original block's
            // bytes in place. The link layout is fixed: name/path/comment at
            // offsets 24/32/40 (only the slots actually referenced by
            // `header.links_nr` are touched).
            let mut bytes = mmap[offset..offset + total_len].to_vec();
            let link_count = header.links_nr as usize;
            if link_count >= 1 {
                bytes[24..32].copy_from_slice(&new_name.to_le_bytes());
            }
            if link_count >= 2 {
                bytes[32..40].copy_from_slice(&new_path.to_le_bytes());
            }
            if link_count >= 3 {
                bytes[40..48].copy_from_slice(&new_comment.to_le_bytes());
            }
            writer.write_block(&bytes)?
        }
        "##CC" => {
            let src_block = ConversionBlock::from_bytes(&mmap[offset..offset + total_len])?;
            cache.insert(src_addr, 0);
            let new_tx_name = clone_block_to_writer(
                writer,
                mmap,
                src_block.cc_tx_name.unwrap_or(0),
                cache,
            )?;
            let new_md_unit = clone_block_to_writer(
                writer,
                mmap,
                src_block.cc_md_unit.unwrap_or(0),
                cache,
            )?;
            let new_md_comment = clone_block_to_writer(
                writer,
                mmap,
                src_block.cc_md_comment.unwrap_or(0),
                cache,
            )?;
            let new_cc_inverse = clone_block_to_writer(
                writer,
                mmap,
                src_block.cc_cc_inverse.unwrap_or(0),
                cache,
            )?;
            let mut new_refs = Vec::with_capacity(src_block.cc_ref.len());
            for &r in &src_block.cc_ref {
                new_refs.push(clone_block_to_writer(writer, mmap, r, cache)?);
            }
            let new_cc = ConversionBlock {
                header: src_block.header.clone(),
                cc_tx_name: (new_tx_name != 0).then_some(new_tx_name),
                cc_md_unit: (new_md_unit != 0).then_some(new_md_unit),
                cc_md_comment: (new_md_comment != 0).then_some(new_md_comment),
                cc_cc_inverse: (new_cc_inverse != 0).then_some(new_cc_inverse),
                cc_ref: new_refs,
                cc_type: src_block.cc_type.clone(),
                cc_precision: src_block.cc_precision,
                cc_flags: src_block.cc_flags,
                cc_ref_count: src_block.cc_ref_count,
                cc_val_count: src_block.cc_val_count,
                cc_phy_range_min: src_block.cc_phy_range_min,
                cc_phy_range_max: src_block.cc_phy_range_max,
                cc_val: src_block.cc_val.clone(),
                formula: None,
                resolved_texts: None,
                resolved_conversions: None,
                default_conversion: None,
            };
            writer.write_block(&new_cc.to_bytes()?)?
        }
        _ => 0,
    };

    if dst != 0 {
        cache.insert(src_addr, dst);
    } else {
        // Drop the cycle-breaker placeholder if cloning ultimately failed.
        cache.remove(&src_addr);
    }
    Ok(dst)
}

/// Cut a segment of an MDF file using **absolute** UNIX-epoch timestamps.
///
/// Unlike [`cut_mdf_by_time`], which interprets its bounds as seconds
/// relative to the master channel's zero, this entry point takes nanosecond
/// timestamps since the UNIX epoch and converts them to relative seconds
/// using the source file's `HD` block start time. This is convenient when
/// the caller already has wall-clock timestamps (e.g. parsed from an ISO
/// 8601 string or a `datetime` object).
///
/// Returns an error if the source file does not record an absolute start
/// time (its `HD.abs_time` is `0`).
///
/// # Arguments
/// * `input_path` - Path to the source MF4 file
/// * `output_path` - Destination path for the trimmed file
/// * `start_ns` - Start of the window in UNIX-epoch nanoseconds (inclusive)
/// * `end_ns` - End of the window in UNIX-epoch nanoseconds (inclusive)
pub fn cut_mdf_by_utc_ns(
    input_path: &str,
    output_path: &str,
    start_ns: i64,
    end_ns: i64,
) -> Result<(), MdfError> {
    // Peek at the source file just to read its absolute start time. This
    // mirrors the parse the main cut routine performs immediately after, but
    // we keep the two parses separate so the time math is self-contained.
    let mdf_for_anchor = MdfFile::parse_from_file(input_path)?;
    let file_start_ns: u64 = mdf_for_anchor.header.abs_time;
    if file_start_ns == 0 {
        return Err(MdfError::BlockSerializationError(
            "source file has no absolute start time (HD.abs_time = 0); \
             cannot cut by UTC timestamps"
                .into(),
        ));
    }
    drop(mdf_for_anchor);

    let anchor = file_start_ns as i128;
    let start_rel_s = (start_ns as i128 - anchor) as f64 / 1.0e9;
    let end_rel_s = (end_ns as i128 - anchor) as f64 / 1.0e9;

    cut_mdf_by_time(input_path, output_path, start_rel_s, end_rel_s)
}

/// Cut a segment of an MDF file based on time stamps.
///
/// The input file is scanned for a master time channel (channel type `2` and
/// sync type `1`). Records whose time value lies in the inclusive range
/// `[start_time, end_time]` are copied byte-for-byte to the output file,
/// preserving:
///
/// * fixed-length numeric, string, and byte-array channels,
/// * per-record invalidation bytes,
/// * VLSD ("signal-based") channels — fresh `##SD` blocks are written in the
///   output, one entry per kept record, and the channel's `data` link is
///   patched to point at them,
/// * per-channel `##CC` conversion, `##SI` source, and `##TX`/`##MD`
///   unit / comment blocks (recursively, including nested conversion
///   chains and source name/path/comment text), as well as the
///   channel-group acquisition name, source, and comment blocks.
///
/// # Arguments
/// * `input_path` - Path to the source MF4 file
/// * `output_path` - Destination path for the trimmed file
/// * `start_time` - Start time of the segment in seconds (inclusive)
/// * `end_time` - End time of the segment in seconds (inclusive)
///
/// # Returns
/// `Ok(())` on success or an [`MdfError`] if reading or writing fails.
pub fn cut_mdf_by_time(
    input_path: &str,
    output_path: &str,
    start_time: f64,
    end_time: f64,
) -> Result<(), MdfError> {
    let mdf = MdfFile::parse_from_file(input_path)?;
    let mut writer = MdfWriter::new(output_path)?;
    writer.init_mdf_file()?;

    // Anchor the cut output to the same wall-clock as the source. Without this
    // the writer's default HD timestamp (a fixed non-epoch value) would be
    // emitted, breaking absolute-time interpretation of the kept records.
    writer.set_start_time(
        mdf.header.abs_time,
        mdf.header.tz_offset,
        mdf.header.daylight_save_time,
        mdf.header.time_flags,
        mdf.header.time_quality,
    )?;

    // Cache mapping source-file block addresses to their freshly written
    // counterparts in the output. Shared across all channels/groups so a
    // text/source/conversion block referenced from multiple places is only
    // emitted once.
    let mut block_cache: HashMap<u64, u64> = HashMap::new();

    for dg in &mdf.data_groups {
        let record_id_len = dg.block.record_id_len;

        // A data group with several channel groups stores interleaved records
        // distinguished by record IDs (unsorted layout). Copying such groups
        // record-by-record with a single record size would corrupt the output,
        // and the writer cannot express two channel groups sharing one data
        // block — refuse loudly instead of writing a broken file.
        if dg.channel_groups.len() > 1 {
            return Err(MdfError::BlockSerializationError(
                "cut: data groups with multiple channel groups (unsorted files) are not supported"
                    .into(),
            ));
        }

        let mut prev_cg: Option<String> = None;
        for cg in &dg.channel_groups {
            let samples_byte_nr = cg.block.samples_byte_nr;
            let invalidation_bytes_nr = cg.block.invalidation_bytes_nr;
            let record_size = record_id_len as usize
                + samples_byte_nr as usize
                + invalidation_bytes_nr as usize;

            let src_record_id = cg.block.record_id;
            let cg_id = writer.add_channel_group(prev_cg.as_deref(), |c| {
                // Records are copied verbatim including any leading record-ID
                // bytes, so the output CG must declare the same record ID.
                c.record_id = src_record_id;
            })?;
            prev_cg = Some(cg_id.clone());

            // Carry over the channel-group acq_name / acq_source / comment
            // blocks from the source. Link offsets in the ##CG block:
            //   40 = acq_name_addr, 48 = acq_source_addr, 64 = comment_addr.
            let cg_pos = writer
                .get_block_position(&cg_id)
                .ok_or_else(|| MdfError::BlockLinkError(format!("cg '{}' not found", cg_id)))?;
            let new_acq_name =
                clone_block_to_writer(&mut writer, &mdf.mmap, cg.block.acq_name_addr, &mut block_cache)?;
            if new_acq_name != 0 {
                writer.update_link(cg_pos + 40, new_acq_name)?;
            }
            let new_acq_source = clone_block_to_writer(
                &mut writer,
                &mdf.mmap,
                cg.block.acq_source_addr,
                &mut block_cache,
            )?;
            if new_acq_source != 0 {
                writer.update_link(cg_pos + 48, new_acq_source)?;
            }
            let new_cg_comment =
                clone_block_to_writer(&mut writer, &mdf.mmap, cg.block.comment_addr, &mut block_cache)?;
            if new_cg_comment != 0 {
                writer.update_link(cg_pos + 64, new_cg_comment)?;
            }

            // Re-create channel blocks in the output. Stale link addresses
            // pointing into the source file are zeroed out so the resulting
            // channel block is self-contained. After the channel block is
            // written, source/conversion/unit/comment blocks are cloned from
            // the source file and the channel's links are patched to point
            // at the freshly written copies. The VLSD `data` link is patched
            // later by `finish_signal_data_block`.
            let mut prev_cn: Option<String> = None;
            // (out_cn_id, source_channel_index, is_vlsd)
            let mut out_channels: Vec<(String, usize, bool)> = Vec::new();
            for (idx, ch) in cg.raw_channels.iter().enumerate() {
                let mut block = ch.block.clone();
                block.resolve_name(&mdf.mmap)?;

                let is_vlsd = block.channel_type == 1 && block.data != 0;

                // Capture the source-file link addresses before zeroing them
                // on the block we hand to `add_channel`.
                let src_source_addr = block.source_addr;
                let src_conversion_addr = block.conversion_addr;
                let src_unit_addr = block.unit_addr;
                let src_comment_addr = block.comment_addr;

                // Drop links to source-file blocks we do not re-emit. Without
                // this, the new file would carry pointers into garbage.
                block.conversion_addr = 0;
                block.conversion = None;
                block.source_addr = 0;
                block.unit_addr = 0;
                block.comment_addr = 0;
                block.component_addr = 0;
                block.data = 0;

                // Preserve the source record layout exactly — records are
                // copied verbatim, so a cloned channel legitimately at byte
                // offset 0 must not be re-positioned by the writer.
                let cn_id = writer.add_channel_preserving_offsets(&cg_id, prev_cn.as_deref(), |c| {
                    *c = block.clone();
                })?;

                // Clone source/conversion/unit/comment blocks (recursively
                // following nested links) and patch the channel's links.
                // Channel block link offsets: source 48, conversion 56,
                // unit 72, comment 80.
                let cn_pos = writer.get_block_position(&cn_id).ok_or_else(|| {
                    MdfError::BlockLinkError(format!("cn '{}' not found", cn_id))
                })?;
                let new_source =
                    clone_block_to_writer(&mut writer, &mdf.mmap, src_source_addr, &mut block_cache)?;
                if new_source != 0 {
                    writer.update_link(cn_pos + 48, new_source)?;
                }
                let new_conv = clone_block_to_writer(
                    &mut writer,
                    &mdf.mmap,
                    src_conversion_addr,
                    &mut block_cache,
                )?;
                if new_conv != 0 {
                    writer.update_link(cn_pos + 56, new_conv)?;
                }
                let new_unit =
                    clone_block_to_writer(&mut writer, &mdf.mmap, src_unit_addr, &mut block_cache)?;
                if new_unit != 0 {
                    writer.update_link(cn_pos + 72, new_unit)?;
                }
                let new_comment =
                    clone_block_to_writer(&mut writer, &mdf.mmap, src_comment_addr, &mut block_cache)?;
                if new_comment != 0 {
                    writer.update_link(cn_pos + 80, new_comment)?;
                }

                prev_cn = Some(cn_id.clone());
                out_channels.push((cn_id, idx, is_vlsd));
            }

            // Open the output DT block using the source's exact record
            // layout (including invalidation bytes), and open one ##SD chain
            // per VLSD channel. We must remember the channel ids before the
            // mutable borrow of the writer ends.
            writer.start_data_block_for_cg_raw(
                &cg_id,
                record_id_len,
                samples_byte_nr,
                invalidation_bytes_nr,
            )?;

            let vlsd_out_ids: Vec<String> = out_channels
                .iter()
                .filter_map(|(cn_id, _, is_vlsd)| {
                    if *is_vlsd { Some(cn_id.clone()) } else { None }
                })
                .collect();
            for cn_id in &vlsd_out_ids {
                writer.start_signal_data_block(cn_id)?;
            }

            // Build VLSD source iterators (lockstep with parent records). For
            // each VLSD channel we also record the inline-slot location and
            // size in the parent record, plus a running offset into the new
            // ##SD block. The inline slot in MDF4 is the byte offset within
            // the SD data section where this entry lives — readers (e.g.
            // asammdf) use it to look up the entry. Since we are writing a
            // freshly numbered SD block, we must overwrite the source-file
            // offsets with offsets valid in the output.
            //
            // Per spec, the slot starts at `record_id_len + byte_offset` and
            // is `bit_count / 8` bytes wide. mf4-rs writes VLSD entries
            // sequentially as `[u32 length][bytes]`, so each entry advances
            // the running offset by `4 + payload.len()`.
            struct VlsdState<'a> {
                cn_id: String,
                slot_off: usize,
                slot_size: usize,
                next_offset: u64,
                iter: Box<dyn Iterator<Item = Result<std::borrow::Cow<'a, [u8]>, MdfError>> + 'a>,
            }
            let mut vlsd_states: Vec<VlsdState> = Vec::new();
            for (cn_id, src_idx, is_vlsd) in &out_channels {
                if *is_vlsd {
                    let ch_block = &cg.raw_channels[*src_idx].block;
                    let slot_size = (ch_block.bit_count / 8) as usize;
                    let slot_off = record_id_len as usize + ch_block.byte_offset as usize;
                    let it = cg.raw_channels[*src_idx].records(dg, cg, &mdf.mmap)?;
                    vlsd_states.push(VlsdState {
                        cn_id: cn_id.clone(),
                        slot_off,
                        slot_size,
                        next_offset: 0,
                        iter: it,
                    });
                }
            }

            // Identify the master/time channel in the source CG.
            let time_idx = cg.raw_channels.iter().position(|c| {
                c.block.channel_type == 2 && c.block.sync_type == 1
            });

            // Iterate raw parent records from the source DT/DL chain.
            let blocks = dg.data_blocks(&mdf.mmap)?;
            for data_block in blocks {
                let raw = data_block.data;
                if record_size == 0 {
                    // Degenerate CG with no record bytes — nothing to do.
                    break;
                }
                let valid_len = (raw.len() / record_size) * record_size;
                for record_chunk in raw[..valid_len].chunks_exact(record_size) {
                    // Pull one VLSD entry per VLSD channel in lockstep with
                    // the parent record, regardless of whether we keep the
                    // record. This keeps the iterators aligned.
                    let mut vlsd_payloads: Vec<Vec<u8>> = Vec::with_capacity(vlsd_states.len());
                    for state in vlsd_states.iter_mut() {
                        match state.iter.next() {
                            Some(Ok(slice)) => vlsd_payloads.push(slice.to_vec()),
                            Some(Err(e)) => return Err(e),
                            None => {
                                return Err(MdfError::BlockSerializationError(
                                    "VLSD entry count fewer than parent records".into(),
                                ));
                            }
                        }
                    }

                    // Decide whether this record falls in the time window.
                    let keep = if let Some(ti) = time_idx {
                        let ch = &cg.raw_channels[ti].block;
                        let raw_val = decode_channel_value(
                            record_chunk,
                            record_id_len as usize,
                            ch,
                        )
                        .unwrap_or(DecodedValue::Unknown);
                        let phys = if let Some(conv) = &ch.conversion {
                            conv.apply_decoded(raw_val, &mdf.mmap)?
                        } else {
                            raw_val
                        };
                        let t = match phys {
                            DecodedValue::Float(f) => f,
                            DecodedValue::UnsignedInteger(u) => u as f64,
                            DecodedValue::SignedInteger(i) => i as f64,
                            _ => continue,
                        };
                        // Scale-aware tolerance keeps timestamps produced by
                        // `i * 0.1`-style accumulation inclusive at both
                        // bounds (an absolute f64::EPSILON is meaningless
                        // once t >> 2). Records outside the window are
                        // skipped rather than aborting the scan, so files
                        // with a non-monotonic master remain correct.
                        let tol_lo = start_time.abs().max(1.0) * 1e-12;
                        let tol_hi = end_time.abs().max(1.0) * 1e-12;
                        t >= start_time - tol_lo && t <= end_time + tol_hi
                    } else {
                        // No master channel — copy everything.
                        true
                    };

                    if keep {
                        // Patch each VLSD inline slot in the parent record so
                        // the offset points at the entry's location in the
                        // freshly written ##SD block. Without this fix-up,
                        // mf4-rs's own reader still works (it walks SD entries
                        // sequentially) but spec-conformant readers like
                        // asammdf — which use the inline offset to locate the
                        // entry — will produce wrong/short results.
                        let needs_patch = vlsd_states
                            .iter()
                            .any(|s| s.slot_size > 0 && s.slot_off + s.slot_size <= record_chunk.len());
                        if needs_patch {
                            let mut patched: Vec<u8> = record_chunk.to_vec();
                            for (state, payload) in vlsd_states.iter().zip(vlsd_payloads.iter()) {
                                if state.slot_size == 0 {
                                    continue;
                                }
                                let end = state.slot_off + state.slot_size;
                                if end > patched.len() {
                                    continue;
                                }
                                let off_bytes = state.next_offset.to_le_bytes();
                                let copy_len = state.slot_size.min(off_bytes.len());
                                patched[state.slot_off..state.slot_off + copy_len]
                                    .copy_from_slice(&off_bytes[..copy_len]);
                                // Zero any trailing bytes when the slot is
                                // wider than 8 (extremely unusual for VLSD).
                                for b in &mut patched[state.slot_off + copy_len..end] {
                                    *b = 0;
                                }
                                let _ = payload; // not used here; advance below
                            }
                            writer.write_raw_record(&cg_id, &patched)?;
                        } else {
                            writer.write_raw_record(&cg_id, record_chunk)?;
                        }
                        for (state, payload) in vlsd_states.iter_mut().zip(vlsd_payloads.iter()) {
                            writer.write_signal_data(&state.cn_id, payload)?;
                            state.next_offset =
                                state.next_offset.saturating_add(4 + payload.len() as u64);
                        }
                    }
                }
            }

            for cn_id in &vlsd_out_ids {
                writer.finish_signal_data_block(cn_id)?;
            }
            writer.finish_data_block(&cg_id)?;
        }
    }

    writer.finalize()
}
