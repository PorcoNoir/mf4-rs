use crate::error::MdfError;
use crate::blocks::channel_block::ChannelBlock;
use crate::blocks::conversion::ConversionType;
use crate::parsing::decoder::{ DecodedValue, decode_channel_value, decode_channel_value_with_validity, decode_f64_from_record, check_value_validity };
use crate::parsing::raw_channel_group::RawChannelGroup;
use crate::parsing::raw_data_group::RawDataGroup;
use crate::parsing::raw_channel::RawChannel;
use crate::parsing::source_info::SourceInfo;
use crate::blocks::common::read_string_block;

/// High level handle for a single channel within a group.
///
/// It holds references to the raw blocks and allows convenient access to
/// metadata and decoded values.
pub struct Channel<'a> {
    block:          &'a ChannelBlock,
    raw_data_group:   &'a RawDataGroup,
    raw_channel_group:     &'a RawChannelGroup,
    raw_channel:    &'a RawChannel,
    mmap:           &'a [u8],
}

impl<'a> Channel<'a> {
    /// Construct a new [`Channel`] from raw block references.
    ///
    /// # Arguments
    /// * `block` - Channel block containing metadata
    /// * `raw_data_group` - Parent data group
    /// * `raw_channel_group` - Parent channel group
    /// * `raw_channel` - Raw channel helper used to iterate samples
    /// * `mmap` - Memory mapped file backing all data
    ///
    /// # Returns
    /// A [`Channel`] handle with no samples decoded yet.
    pub fn new(
        block: &'a ChannelBlock,
        raw_data_group: &'a RawDataGroup,
        raw_channel_group: &'a RawChannelGroup,
        raw_channel: &'a RawChannel,
        mmap: &'a [u8],
    ) -> Self {
        Channel { block, raw_data_group, raw_channel_group, raw_channel, mmap }
    }
    /// Retrieve the channel name if present.
    pub fn name(&self) -> Result<Option<String>, MdfError> {
        read_string_block(self.mmap, self.block.name_addr)
    }

    /// Retrieve the physical unit description.
    pub fn unit(&self) -> Result<Option<String>, MdfError> {
        read_string_block(self.mmap, self.block.unit_addr)
    }

    /// Retrieve the channel comment if present.
    pub fn comment(&self) -> Result<Option<String>, MdfError> {
        read_string_block(self.mmap, self.block.comment_addr)
    }

    /// Get the acquisition source for this channel if available.
    pub fn source(&self) -> Result<Option<SourceInfo>, MdfError> {
        let addr = self.block.source_addr;
        SourceInfo::from_mmap(self.mmap, addr)
    }

    /// Decode and convert all samples of this channel.
    ///
    /// This method decodes all channel values and applies conversions.
    /// Invalid samples (as indicated by invalidation bits) are returned as `None`.
    ///
    /// # Returns
    /// A vector with one `Option<DecodedValue>` per record:
    /// - `Some(value)` for valid samples
    /// - `None` for invalid samples (invalidation bit set or decoding failed)
    pub fn values(&self) -> Result<Vec<Option<DecodedValue>>, MdfError> {
        let record_id_len = self.raw_data_group.block.record_id_len as usize;
        let cg_data_bytes = self.raw_channel_group.block.samples_byte_nr;
        let invalidation_bytes_nr = self.raw_channel_group.block.invalidation_bytes_nr;
        let capacity = self.raw_channel_group.block.cycles_nr as usize;
        let mut out = Vec::with_capacity(capacity);

        // cn_flags bit 0: all values invalid, regardless of invalidation bytes
        let all_invalid = self.block.flags & 0x01 != 0;

        // VLSD channels must use the boxed iterator path. The iterator yields
        // the variable-length payload, not the fixed record, so per-record
        // invalidation bits cannot be checked here — only the all-invalid flag.
        if self.block.channel_type == 1 && self.block.data != 0 {
            let records_iter = self
                .raw_channel
                .records(self.raw_data_group, self.raw_channel_group, self.mmap)?;
            for rec_res in records_iter {
                let ref rec = rec_res?;
                if all_invalid {
                    out.push(None);
                } else if let Some(decoded) = decode_channel_value(rec, record_id_len, self.block) {
                    let phys = self.block.apply_conversion_value(decoded, self.mmap)?;
                    out.push(Some(phys));
                } else {
                    out.push(None);
                }
            }
            return Ok(out);
        }

        // Fast path: iterate over data blocks directly without Box<dyn Iterator>
        let sample_byte_len = cg_data_bytes as usize;
        let invalidation_bytes = invalidation_bytes_nr as usize;
        let record_size = record_id_len + sample_byte_len + invalidation_bytes;

        if record_size == 0 {
            return Ok(out);
        }

        let blocks = self.raw_data_group.data_blocks(self.mmap)?;

        if invalidation_bytes_nr == 0 && !all_invalid {
            // Fast path: no invalidation bytes and no all-invalid flag
            for data_block in &blocks {
                let raw = data_block.data.as_ref();
                let valid_len = (raw.len() / record_size) * record_size;
                let mut offset = 0;
                while offset + record_size <= valid_len {
                    let rec = &raw[offset..offset + record_size];
                    if let Some(decoded) = decode_channel_value(rec, record_id_len, self.block) {
                        let phys = self.block.apply_conversion_value(decoded, self.mmap)?;
                        out.push(Some(phys));
                    } else {
                        out.push(None);
                    }
                    offset += record_size;
                }
            }
        } else {
            // Slow path: must check invalidation flags/bits per record
            for data_block in &blocks {
                let raw = data_block.data.as_ref();
                let valid_len = (raw.len() / record_size) * record_size;
                let mut offset = 0;
                while offset + record_size <= valid_len {
                    let rec = &raw[offset..offset + record_size];
                    if let Some(decoded) = decode_channel_value_with_validity(
                        rec, record_id_len, cg_data_bytes, self.block
                    ) {
                        if decoded.is_valid {
                            let phys = self.block.apply_conversion_value(decoded.value, self.mmap)?;
                            out.push(Some(phys));
                        } else {
                            out.push(None);
                        }
                    } else {
                        out.push(None);
                    }
                    offset += record_size;
                }
            }
        }
        Ok(out)
    }

    /// Decode all samples as **physical** f64 values.
    ///
    /// This is significantly faster than `values()` for numeric channels
    /// because it avoids the `Option<DecodedValue>` wrapping. Conversions are
    /// applied (with a fast inline path for linear conversions) and samples
    /// flagged invalid via invalidation bits or the all-invalid channel flag
    /// are returned as NaN — matching `MdfIndex`'s `values_f64` semantics.
    /// Non-numeric results (e.g. text conversions) are returned as NaN.
    pub fn values_as_f64(&self) -> Result<Vec<f64>, MdfError> {
        let record_id_len = self.raw_data_group.block.record_id_len as usize;
        let cg_data_bytes = self.raw_channel_group.block.samples_byte_nr;
        let capacity = self.raw_channel_group.block.cycles_nr as usize;
        let mut out = Vec::with_capacity(capacity);

        let all_invalid = self.block.flags & 0x01 != 0;
        let conv = self.block.conversion.as_ref();
        let has_conversion = conv.map_or(false, |c| c.cc_type != ConversionType::Identity);
        let linear_coeffs = conv.and_then(|c| {
            if c.cc_type == ConversionType::Linear && c.cc_val.len() >= 2 {
                Some((c.cc_val[0], c.cc_val[1]))
            } else {
                None
            }
        });

        // Applies conversion to one raw record slice, returning the physical f64.
        let convert_record = |rec: &[u8], out: &mut Vec<f64>| -> Result<(), MdfError> {
            if let Some((a, b)) = linear_coeffs {
                let raw = decode_f64_from_record(rec, record_id_len, self.block);
                out.push(a + b * raw);
            } else if has_conversion {
                if let Some(decoded) = decode_channel_value(rec, record_id_len, self.block) {
                    match self.block.apply_conversion_value(decoded, self.mmap)? {
                        DecodedValue::Float(v) => out.push(v),
                        DecodedValue::UnsignedInteger(v) => out.push(v as f64),
                        DecodedValue::SignedInteger(v) => out.push(v as f64),
                        _ => out.push(f64::NAN),
                    }
                } else {
                    out.push(f64::NAN);
                }
            } else {
                out.push(decode_f64_from_record(rec, record_id_len, self.block));
            }
            Ok(())
        };

        // VLSD channels must use the boxed iterator path. Only the all-invalid
        // flag can be checked (the iterator yields payloads, not records).
        if self.block.channel_type == 1 && self.block.data != 0 {
            let records_iter = self
                .raw_channel
                .records(self.raw_data_group, self.raw_channel_group, self.mmap)?;
            for rec_res in records_iter {
                let rec = rec_res?;
                if all_invalid {
                    out.push(f64::NAN);
                } else {
                    convert_record(rec.as_ref(), &mut out)?;
                }
            }
            return Ok(out);
        }

        // Fast path: iterate over data blocks directly without Box<dyn Iterator>
        let sample_byte_len = cg_data_bytes as usize;
        let invalidation_bytes = self.raw_channel_group.block.invalidation_bytes_nr as usize;
        let record_size = record_id_len + sample_byte_len + invalidation_bytes;

        if record_size == 0 {
            return Ok(out);
        }

        let blocks = self.raw_data_group.data_blocks(self.mmap)?;
        for data_block in &blocks {
            let raw = data_block.data.as_ref();
            let valid_len = (raw.len() / record_size) * record_size;
            let mut offset = 0;
            while offset + record_size <= valid_len {
                let rec = &raw[offset..offset + record_size];
                if all_invalid
                    || (invalidation_bytes > 0
                        && !check_value_validity(rec, record_id_len, cg_data_bytes, self.block))
                {
                    out.push(f64::NAN);
                } else {
                    convert_record(rec, &mut out)?;
                }
                offset += record_size;
            }
        }
        Ok(out)
    }

    /// Get the channel block (for internal use)
    pub fn block(&self) -> &ChannelBlock {
        self.block
    }
}
