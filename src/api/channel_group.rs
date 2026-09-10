use crate::blocks::common::read_string_block;
use crate::parsing::raw_data_group::RawDataGroup;
use crate::parsing::raw_channel_group::RawChannelGroup;
use crate::parsing::source_info::SourceInfo;
use crate::api::channel::Channel;
use crate::error::MdfError;
use crate::signal::{Signal, SignalF64};

/// High level wrapper for a channel group.
///
/// The struct references raw channel group data and provides ergonomic access
/// to its metadata and channels without decoding any actual samples.
pub struct ChannelGroup<'a> {
    raw_data_group:    &'a RawDataGroup,
    raw_channel_group: &'a RawChannelGroup,
    mmap:              &'a [u8],
}

impl<'a> ChannelGroup<'a> {
    /// Create a new [`ChannelGroup`] referencing the underlying raw blocks.
    ///
    /// # Arguments
    /// * `raw_data_group` - Parent data group containing this channel group
    /// * `raw_channel_group` - The raw channel group block
    /// * `mmap` - Memory mapped file backing all data
    ///
    /// # Returns
    /// A [`ChannelGroup`] handle with no decoded data.
    pub fn new(
        raw_data_group: &'a RawDataGroup,
        raw_channel_group: &'a RawChannelGroup,
        mmap: &'a [u8],
    ) -> Self {
        ChannelGroup { raw_data_group, raw_channel_group, mmap }
    }

    /// Retrieve the human readable group name.
    pub fn name(&self) -> Result<Option<String>, MdfError> {
        read_string_block(self.mmap, self.raw_channel_group.block.acq_name_addr)
    }

    /// Retrieve the group comment if present.
    pub fn comment(&self) -> Result<Option<String>, MdfError> {
        read_string_block(self.mmap, self.raw_channel_group.block.comment_addr)
    }

    /// Get the acquisition source information if available.
    pub fn source(&self) -> Result<Option<SourceInfo>, MdfError> {
        let addr = self.raw_channel_group.block.acq_source_addr;
        SourceInfo::from_mmap(self.mmap, addr)
    }

    /// Build all [`Channel`] objects for this group.
    ///
    /// No channel data is decoded; the returned channels simply reference the
    /// raw blocks.
    pub fn channels(&self) -> Vec<Channel<'a>> {

        let mut channels = Vec::new();
        for raw_channel in &self.raw_channel_group.raw_channels {
            let channel = Channel::new(
                &raw_channel.block,
                self.raw_data_group,
                self.raw_channel_group,
                raw_channel,
                self.mmap,
            );
            channels.push(channel);
        }

        channels
    }

    /// Find a channel in this group by name (first match).
    pub fn channel(&self, name: &str) -> Option<Channel<'a>> {
        self.channels()
            .into_iter()
            .find(|c| c.name().ok().flatten().as_deref() == Some(name))
    }

    /// Read a channel by name as a [`Signal`] (values paired with the group's
    /// master/time axis).
    ///
    /// Returns `Ok(None)` if no channel with that name exists in this group.
    /// `timestamps` is empty when the group has no master channel or when the
    /// requested channel *is* the master.
    pub fn signal(&self, name: &str) -> Result<Option<Signal>, MdfError> {
        let channels = self.channels();
        let mut target: Option<usize> = None;
        let mut master: Option<usize> = None;
        for (i, ch) in channels.iter().enumerate() {
            // First master wins (matches MdfIndex's master selection)
            if master.is_none() && ch.block().channel_type == 2 {
                master = Some(i);
            }
            if target.is_none() && ch.name()?.as_deref() == Some(name) {
                target = Some(i);
            }
        }
        let Some(ci) = target else { return Ok(None) };

        let values = channels[ci].values()?;
        let timestamps = match master {
            Some(mi) if mi != ci => channels[mi].values_as_f64()?,
            _ => Vec::new(),
        };
        Ok(Some(Signal {
            name: name.to_string(),
            unit: channels[ci].unit()?,
            timestamps,
            values,
        }))
    }

    /// Decode several channels — plus the master axis — in **one pass** over
    /// the group's data blocks.
    ///
    /// [`signal`](Self::signal) walks (and, for compressed files, inflates)
    /// every data block once for the target and once more for the master, so
    /// reading N channels of a group costs 2N full passes. This reads the
    /// blocks once and extracts all requested channels record by record:
    /// opening a many-channel plot goes from O(N × group) to O(group).
    ///
    /// The result is index-aligned with `names`; `None` marks a name with no
    /// channel in this group. When no name matches, the data blocks are not
    /// touched at all. Value semantics match [`Channel::values_as_f64`]
    /// (physical values, `NaN` for invalid or non-numeric samples); axis
    /// semantics match [`signal`](Self::signal). Variable-length (VLSD)
    /// channels fall back to their per-channel path.
    pub fn signals_f64(&self, names: &[&str]) -> Result<Vec<Option<SignalF64>>, MdfError> {
        use crate::blocks::conversion::ConversionType;
        use crate::parsing::decoder::{
            check_value_validity, decode_channel_value, decode_f64_from_record, DecodedValue,
        };

        let channels = self.channels();
        let mut master: Option<usize> = None;
        // Requested-name slot → channel index (first match, as `signal`).
        let mut targets: Vec<Option<usize>> = vec![None; names.len()];
        for (i, ch) in channels.iter().enumerate() {
            if master.is_none() && ch.block().channel_type == 2 {
                master = Some(i);
            }
            if let Some(n) = ch.name()?.as_deref() {
                for (slot, t) in targets.iter_mut().enumerate() {
                    if t.is_none() && names[slot] == n {
                        *t = Some(i);
                    }
                }
            }
        }
        if targets.iter().all(Option::is_none) {
            return Ok(vec![None; names.len()]);
        }

        // Per-channel decode state, mirroring `Channel::values_as_f64`.
        struct Slot<'b> {
            block: &'b crate::blocks::channel_block::ChannelBlock,
            all_invalid: bool,
            linear: Option<(f64, f64)>,
            has_conversion: bool,
            values: Vec<f64>,
        }
        let capacity = self.raw_channel_group.block.cycles_nr as usize;
        let make_slot = |ci: usize| {
            let block = channels[ci].block();
            let conv = block.conversion.as_ref();
            Slot {
                block,
                all_invalid: block.flags & 0x01 != 0,
                linear: conv.and_then(|c| {
                    if c.cc_type == ConversionType::Linear && c.cc_val.len() >= 2 {
                        Some((c.cc_val[0], c.cc_val[1]))
                    } else {
                        None
                    }
                }),
                has_conversion: conv.map_or(false, |c| c.cc_type != ConversionType::Identity),
                values: Vec::with_capacity(capacity),
            }
        };

        // The pass decodes each *distinct* fixed-record channel once; VLSD
        // channels can't ride a fixed-record walk and fall back below.
        let mut decode: Vec<(usize, Slot)> = Vec::new(); // (channel idx, state)
        for ci in targets.iter().flatten() {
            let is_vlsd = channels[*ci].block().channel_type == 1 && channels[*ci].block().data != 0;
            if !is_vlsd && !decode.iter().any(|(d, _)| d == ci) {
                decode.push((*ci, make_slot(*ci)));
            }
        }
        if let Some(mi) = master {
            if !decode.iter().any(|(d, _)| d == &mi) {
                decode.push((mi, make_slot(mi)));
            }
        }

        let record_id_len = self.raw_data_group.block.record_id_len as usize;
        let cg_data_bytes = self.raw_channel_group.block.samples_byte_nr;
        let invalidation_bytes = self.raw_channel_group.block.invalidation_bytes_nr as usize;
        let record_size = record_id_len + cg_data_bytes as usize + invalidation_bytes;
        if record_size > 0 && !decode.is_empty() {
            let blocks = self.raw_data_group.data_blocks(self.mmap)?;
            for data_block in &blocks {
                let raw = data_block.data.as_ref();
                let valid_len = (raw.len() / record_size) * record_size;
                let mut offset = 0;
                while offset + record_size <= valid_len {
                    let rec = &raw[offset..offset + record_size];
                    for (_, slot) in decode.iter_mut() {
                        let v = if slot.all_invalid
                            || (invalidation_bytes > 0
                                && !check_value_validity(
                                    rec,
                                    record_id_len,
                                    cg_data_bytes,
                                    slot.block,
                                )) {
                            f64::NAN
                        } else if let Some((a, b)) = slot.linear {
                            a + b * decode_f64_from_record(rec, record_id_len, slot.block)
                        } else if slot.has_conversion {
                            match decode_channel_value(rec, record_id_len, slot.block) {
                                Some(decoded) => {
                                    match slot.block.apply_conversion_value(decoded, self.mmap)? {
                                        DecodedValue::Float(f) => f,
                                        DecodedValue::UnsignedInteger(u) => u as f64,
                                        DecodedValue::SignedInteger(i) => i as f64,
                                        _ => f64::NAN,
                                    }
                                }
                                None => f64::NAN,
                            }
                        } else {
                            decode_f64_from_record(rec, record_id_len, slot.block)
                        };
                        slot.values.push(v);
                    }
                    offset += record_size;
                }
            }
        }
        let decoded: std::collections::HashMap<usize, Vec<f64>> =
            decode.into_iter().map(|(ci, s)| (ci, s.values)).collect();
        let timestamps = master
            .and_then(|mi| decoded.get(&mi))
            .cloned()
            .unwrap_or_default();

        let mut out = Vec::with_capacity(names.len());
        for (slot, target) in targets.iter().enumerate() {
            let Some(ci) = target else {
                out.push(None);
                continue;
            };
            let values = match decoded.get(ci) {
                Some(v) => v.clone(),
                // VLSD fallback: the existing per-channel path.
                None => channels[*ci].values_as_f64()?,
            };
            // A master indexes itself: no separate axis (as `signal`).
            let ts = if master == Some(*ci) { Vec::new() } else { timestamps.clone() };
            out.push(Some(SignalF64 {
                name: names[slot].to_string(),
                unit: channels[*ci].unit()?,
                timestamps: ts,
                values,
            }));
        }
        Ok(out)
    }

    /// Get the raw data group (for internal use)
    pub fn raw_data_group(&self) -> &RawDataGroup {
        self.raw_data_group
    }

    /// Get the raw channel group (for internal use) 
    pub fn raw_channel_group(&self) -> &RawChannelGroup {
        self.raw_channel_group
    }

    /// Get the memory mapped data (for internal use)
    pub fn mmap(&self) -> &[u8] {
        self.mmap
    }
}
