use crate::error::MdfError;
use crate::parsing::raw_channel_group::RawChannelGroup;
use crate::blocks::{
    data_block::DataBlock,
    data_group_block::DataGroupBlock,
    data_list_block::DataListBlock,
    common::BlockHeader,
    common::BlockParse,
};

#[derive(Debug)]
pub struct RawDataGroup {
    pub block: DataGroupBlock,
    pub channel_groups: Vec<RawChannelGroup>,
}
impl RawDataGroup {

    /// Collect all data blocks referenced by this data group.
    ///
    /// The returned vector contains the `DT` or `DV` blocks in the order they
    /// appear on disk, transparently following any `DL` list chains.
    ///
    /// # Arguments
    /// * `mmap` - Memory mapped file containing the MDF data
    ///
    /// # Returns
    /// A vector of [`DataBlock`] objects or an [`MdfError`] if parsing fails.
    pub fn data_blocks<'a>(
        &self,
        mmap: &'a [u8],
    ) -> Result<Vec<DataBlock<'a>>, MdfError> {
        // Unsorted data groups interleave records of several channel groups
        // (each prefixed by a record id). Framing them as fixed-size records
        // of a single group silently mis-decodes the data, so refuse loudly.
        // Metadata access (names, channels) is unaffected — only record/data
        // access goes through here.
        if self.block.record_id_len > 0 && self.channel_groups.len() > 1 {
            return Err(MdfError::BlockSerializationError(
                "unsorted data groups (multiple channel groups per data group) are not supported"
                    .to_string(),
            ));
        }

        let mut collected_blocks = Vec::new();

        // Start at the group’s primary data pointer
        let mut current_block_address = self.block.data_block_addr;
        let mut visited = std::collections::HashSet::new();
        while current_block_address != 0 {
            if !visited.insert(current_block_address) {
                return Err(MdfError::BlockLinkError(format!(
                    "cycle detected in data block chain at address {:#x}",
                    current_block_address
                )));
            }
            let byte_offset = current_block_address as usize;

            // Read the block header (bounds-checked)
            let header_bytes = mmap
                .get(byte_offset..byte_offset.saturating_add(24))
                .ok_or(MdfError::TooShortBuffer {
                    actual:   mmap.len(),
                    expected: byte_offset.saturating_add(24),
                    file:     file!(),
                    line:     line!(),
                })?;
            let block_header = BlockHeader::from_bytes(header_bytes)?;

            match block_header.id.as_str() {
                "##DT" | "##DV" | "##DZ" => {
                    // Single contiguous block — plain, or inflated from DZ.
                    let data_block = parse_data_fragment(&mmap[byte_offset..])?;
                    collected_blocks.push(data_block);
                    // No list to follow, we’re done
                    current_block_address = 0;
                }
                "##HL" => {
                    // Header list wrapping a compressed chain: a 24-byte
                    // header, one link (the first DL), then zip flags the DZ
                    // fragments repeat anyway. Follow the link.
                    let link_bytes = mmap.get(byte_offset + 24..byte_offset + 32).ok_or(
                        MdfError::TooShortBuffer {
                            actual:   mmap.len(),
                            expected: byte_offset.saturating_add(32),
                            file:     file!(),
                            line:     line!(),
                        },
                    )?;
                    current_block_address = u64::from_le_bytes(link_bytes.try_into().unwrap());
                }
                "##DL" => {
                    // Fragmented list of data blocks
                    let data_list_block = DataListBlock::from_bytes(&mmap[byte_offset..])?;

                    // Parse each fragment in this list
                    for &fragment_address in &data_list_block.data_links {
                        if fragment_address == 0 {
                            continue; // null link
                        }
                        let fragment_offset = fragment_address as usize;
                        let fragment_bytes =
                            mmap.get(fragment_offset..).ok_or(MdfError::TooShortBuffer {
                                actual:   mmap.len(),
                                expected: fragment_offset.saturating_add(24),
                                file:     file!(),
                                line:     line!(),
                            })?;
                        let fragment_block = parse_data_fragment(fragment_bytes)?;

                        collected_blocks.push(fragment_block);
                    }

                    // Move to the next DLBLOCK in the chain (0 = end)
                    current_block_address = data_list_block.next;
                }

                unexpected_id => {
                    return Err(MdfError::BlockIDError {
                        actual: unexpected_id.to_string(),
                        expected: "##DT / ##DV / ##DL / ##DZ / ##HL".to_string(),
                    });
                }
            }
        }

        Ok(collected_blocks)
    }
}

/// One data fragment: a plain `##DT`/`##DV` borrows the mmap; a compressed
/// `##DZ` is inflated (deflate, plus the transposed variant measurement
/// tools default to) into an owned block.
fn parse_data_fragment(bytes: &[u8]) -> Result<DataBlock<'_>, MdfError> {
    let header = BlockHeader::from_bytes(bytes)?;
    if header.id != "##DZ" {
        return DataBlock::from_bytes(bytes);
    }

    // DZBLOCK layout after the 24-byte header:
    //   org_block_type: [u8; 2]   ("DT"/"DV"/"SD"/"RD")
    //   zip_type:       u8        (0 = deflate, 1 = transposed deflate)
    //   reserved:       u8
    //   zip_parameter:  u32       (transposition column count)
    //   org_data_length:u64
    //   data_length:    u64
    let need = 24 + 24;
    if bytes.len() < need {
        return Err(MdfError::TooShortBuffer {
            actual:   bytes.len(),
            expected: need,
            file:     file!(),
            line:     line!(),
        });
    }
    let zip_type = bytes[26];
    let zip_parameter = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
    let org_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let data_len = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let payload = bytes.get(48..48 + data_len).ok_or(MdfError::TooShortBuffer {
        actual:   bytes.len(),
        expected: 48 + data_len,
        file:     file!(),
        line:     line!(),
    })?;

    let inflated = miniz_oxide::inflate::decompress_to_vec_zlib(payload)
        .map_err(|e| MdfError::BlockSerializationError(format!("DZ inflate failed: {e:?}")))?;

    let data = match zip_type {
        0 => inflated,
        1 => untranspose(&inflated, zip_parameter, org_len),
        other => {
            return Err(MdfError::BlockSerializationError(format!(
                "DZ zip_type {other} is not supported"
            )));
        }
    };
    if data.len() != org_len {
        return Err(MdfError::BlockSerializationError(format!(
            "DZ inflated to {} bytes, expected {org_len}",
            data.len()
        )));
    }
    Ok(DataBlock::from_owned(header, data))
}

/// Undo transposed deflate: the compressor reshaped the original bytes into
/// `cols` columns and stored the transpose (better ratios on record data);
/// any tail shorter than a full row is appended untransposed.
fn untranspose(transposed: &[u8], cols: usize, org_len: usize) -> Vec<u8> {
    if cols == 0 || transposed.len() < cols {
        return transposed.to_vec();
    }
    let lines = org_len / cols;
    let body = lines * cols;
    let mut out = Vec::with_capacity(transposed.len());
    for i in 0..lines {
        for j in 0..cols {
            out.push(transposed[j * lines + i]);
        }
    }
    out.extend_from_slice(&transposed[body.min(transposed.len())..]);
    out
}