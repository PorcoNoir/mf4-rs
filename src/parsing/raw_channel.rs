use crate::blocks::channel_block::ChannelBlock;
use crate::blocks::data_list_block::DataListBlock;
use crate::blocks::signal_data_block::SignalDataBlock;
use std::borrow::Cow;
use crate::blocks::common::BlockParse;
use crate::parsing::raw_channel_group::RawChannelGroup;
use crate::parsing::raw_data_group::RawDataGroup;
use crate::error::MdfError;

/// A channel with lazy access to its raw record bytes (fixed-length or VLSD).
#[derive(Debug)]
pub struct RawChannel {
    pub block:  ChannelBlock,
}

impl<'a> RawChannel {

    /// Return an iterator over raw record bytes for this channel.
    ///
    /// The iterator yields a `Result` for each record and transparently handles
    /// both fixed-size and VLSD storage schemes.
    ///
    /// # Arguments
    /// * `data_group` - Parent data group owning the records
    /// * `channel_group` - Channel group this channel belongs to
    /// * `mmap` - Memory mapped MDF data
    ///
    /// # Returns
    /// An iterator over byte slices containing each raw record, or an
    /// [`MdfError`] if the underlying blocks could not be parsed.
    pub fn records(
        &self,
        data_group: &'a RawDataGroup,
        channel_group: &'a RawChannelGroup,
        mmap: &'a [u8],
    ) -> Result<Box<dyn Iterator<Item = Result<Cow<'a, [u8]>, MdfError>> + 'a>, MdfError> {
        // 1) VLSD path: channel has its own data pointer => SD/DL chain
        if self.block.channel_type == 1 && self.block.data != 0 {
            // Capture the file bytes and channel pointer
            let bytes = mmap;
            let mut next_addr = self.block.data;
            let mut data_links = Vec::new();
            let mut link_idx = 0;
            let mut current_sdb: Option<SignalDataBlock> = None;
            let mut sdb_pos = 0;
            let mut visited_dl: std::collections::HashSet<u64> = std::collections::HashSet::new();

            // Build a from_fn iterator carrying that mutable state
            let vlsd_iter = std::iter::from_fn(move || -> Option<Result<Cow<'a, [u8]>, MdfError>> {
                loop {
                    // 1) Yield from an open SDBLOCK if any
                    if let Some(sdb) = &current_sdb {
                        let buf = sdb.data;
                        if sdb_pos + 4 <= buf.len() {
                            let len = u32::from_le_bytes(
                                buf[sdb_pos..sdb_pos+4].try_into().unwrap()
                            ) as usize;
                            let start = sdb_pos + 4;
                            let end = start + len;
                            if end > buf.len() {
                                return Some(Err(MdfError::TooShortBuffer {
                                    actual:   buf.len(),
                                    expected: end,
                                    file:     file!(),
                                    line:     line!(),
                                }));
                            }
                            let slice = &buf[start..end];
                            sdb_pos = end;
                            return Some(Ok(Cow::Borrowed(slice)));
                        }
                        // exhausted
                        current_sdb = None;
                    }

                    // 2) Next link in current DL batch?
                    if link_idx < data_links.len() {
                        let frag_addr = data_links[link_idx];
                        link_idx += 1;
                        if frag_addr == 0 {
                            continue; // null link
                        }
                        let off = frag_addr as usize;
                        if off >= bytes.len() {
                            return Some(Err(MdfError::TooShortBuffer {
                                actual:   bytes.len(),
                                expected: off.saturating_add(24),
                                file:     file!(),
                                line:     line!(),
                            }));
                        }
                        match SignalDataBlock::from_bytes(&bytes[off..]) {
                            Ok(sdb) => {
                                // Prepare to yield from it on the next loop
                                current_sdb = Some(sdb);
                                sdb_pos = 0;
                                continue;
                            }
                            Err(e) => return Some(Err(e.into())),
                        }
                    }

                    // 3) If we have a next_addr, peek its ID to decide what it is
                    if next_addr != 0 {
                        // Cycle detection: a chain that revisits an address
                        // would otherwise loop forever.
                        if !visited_dl.insert(next_addr) {
                            return Some(Err(MdfError::BlockLinkError(format!(
                                "cycle detected in VLSD data chain at address {:#x}",
                                next_addr
                            ))));
                        }
                        let off = next_addr as usize;
                        // read the 4-byte ID (bounds-checked)
                        let id = match bytes.get(off..off.saturating_add(4)) {
                            Some(id) => id,
                            None => {
                                return Some(Err(MdfError::TooShortBuffer {
                                    actual:   bytes.len(),
                                    expected: off.saturating_add(4),
                                    file:     file!(),
                                    line:     line!(),
                                }));
                            }
                        };
                        match id {
                            b"##DL" => {
                                // Data List Block
                                match DataListBlock::from_bytes(&bytes[off..]) {
                                    Ok(dl) => {
                                        data_links = dl.data_links.clone();
                                        link_idx = 0;
                                        next_addr = dl.next;
                                        continue;  // back to loop start
                                    }
                                    Err(e) => return Some(Err(e)),
                                }
                            }
                            b"##SD" => {
                                // Direct Signal Data Block
                                match SignalDataBlock::from_bytes(&bytes[off..]) {
                                    Ok(sdb) => {
                                        current_sdb = Some(sdb);
                                        sdb_pos = 0;
                                        next_addr = 0; // no list chain
                                        continue;
                                    }
                                    Err(e) => return Some(Err(e)),
                                }
                            }
                            other => {
                                // unexpected block type
                                return Some(Err(MdfError::BlockIDError {
                                    actual:   String::from_utf8_lossy(other).into(),
                                    expected: "##DL or ##SD".to_string(),
                                }));
                            }
                        }
                    }

                    // 4) Done
                    return None;
                }
            });

            return Ok(Box::new(vlsd_iter));
        }

        // Compute the size of each record:
        // Record structure: record_id + data_bytes + invalidation_bytes
        let record_id_len       = data_group.block.record_id_len as usize;
        let sample_byte_len     = channel_group.block.samples_byte_nr as usize;
        let invalidation_bytes  = channel_group.block.invalidation_bytes_nr as usize;
        let record_size         = record_id_len + sample_byte_len + invalidation_bytes;

        // A record size of zero (malformed channel group) would make the
        // chunking below divide by zero / panic — there are no records.
        if record_size == 0 {
            return Ok(Box::new(std::iter::empty()));
        }

        // Gather all DataBlock fragments (DT, DV or DZ):
        let blocks = data_group.data_blocks(mmap)?;

        // Build a single iterator that:
        //  - goes block by block
        //  - trims any partial record at the end of each block
        //  - yields & [u8] of length `record_size`
        let iter = blocks.into_iter().flat_map(move |data_block| {
            // Plain blocks yield zero-copy borrows from the mmap; DZ-inflated
            // blocks own their bytes, so their records are copied out.
            let recs: Vec<Result<Cow<'a, [u8]>, MdfError>> = match data_block.data {
                Cow::Borrowed(raw) => {
                    let valid_len = (raw.len() / record_size) * record_size;
                    raw[..valid_len]
                        .chunks_exact(record_size)
                        .map(|c| Ok(Cow::Borrowed(c)))
                        .collect()
                }
                Cow::Owned(vec) => {
                    let valid_len = (vec.len() / record_size) * record_size;
                    vec[..valid_len]
                        .chunks_exact(record_size)
                        .map(|c| Ok(Cow::Owned(c.to_vec())))
                        .collect()
                }
            };
            recs.into_iter()
        });

        Ok(Box::new(iter))
    }
}

