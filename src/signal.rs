//! A decoded signal: a channel's samples paired with their master (time) axis.
//!
//! [`Signal`] is the Rust equivalent of a pandas `Series` — `values` indexed by
//! `timestamps`. It is produced by the high-level readers ([`MDF::signal`],
//! [`crate::index::MdfReader::signal`], [`crate::index::MdfIndex::read`]).
//!
//! [`MDF::signal`]: crate::api::mdf::MDF::signal

use crate::parsing::decoder::DecodedValue;

/// A channel's samples together with the group's master (time) axis.
///
/// `timestamps` holds the master channel's values in seconds. It is empty when
/// the group has no master channel, or when the requested channel *is* the
/// master (a master signal indexes itself). `values` always has one entry per
/// record (`None` marks an invalid sample), with conversions applied.
#[derive(Debug, Clone)]
pub struct Signal {
    /// Channel name.
    pub name: String,
    /// Physical unit, if any.
    pub unit: Option<String>,
    /// Master-channel values (seconds). Empty if there is no separate master.
    pub timestamps: Vec<f64>,
    /// One decoded value per record (`None` = invalid sample).
    pub values: Vec<Option<DecodedValue>>,
}

impl Signal {
    /// Number of samples.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// `true` if the signal has no samples.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// `true` if a separate master/time axis is attached.
    pub fn has_timestamps(&self) -> bool {
        !self.timestamps.is_empty()
    }

    /// Values as `f64`, with `NaN` for invalid or non-numeric samples.
    pub fn values_f64(&self) -> Vec<f64> {
        self.values.iter().map(decoded_opt_to_f64).collect()
    }
}

/// Map an optional decoded value to `f64` (`NaN` for `None`/non-numeric).
pub(crate) fn decoded_opt_to_f64(v: &Option<DecodedValue>) -> f64 {
    match v {
        Some(DecodedValue::Float(f)) => *f,
        Some(DecodedValue::UnsignedInteger(u)) => *u as f64,
        Some(DecodedValue::SignedInteger(i)) => *i as f64,
        _ => f64::NAN,
    }
}

/// A channel decoded straight to `f64` by the one-pass bulk readers
/// ([`ChannelGroup::signals_f64`], [`MDF::signals_f64`]).
///
/// Same axis semantics as [`Signal`]: `timestamps` holds the master values
/// (empty when the group has no master, or the channel *is* the master);
/// invalid or non-numeric samples decode to `NaN` — matching
/// [`Signal::values_f64`].
///
/// [`ChannelGroup::signals_f64`]: crate::api::channel_group::ChannelGroup::signals_f64
/// [`MDF::signals_f64`]: crate::api::mdf::MDF::signals_f64
#[derive(Debug, Clone)]
pub struct SignalF64 {
    /// Channel name.
    pub name: String,
    /// Physical unit, if any.
    pub unit: Option<String>,
    /// Master-channel values. Empty if there is no separate master.
    pub timestamps: Vec<f64>,
    /// One physical value per record (`NaN` = invalid / non-numeric).
    pub values: Vec<f64>,
}
