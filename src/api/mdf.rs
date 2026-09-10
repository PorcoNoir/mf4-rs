use crate::error::MdfError;
use crate::parsing::mdf_file::MdfFile;
use crate::api::channel_group::ChannelGroup;
use crate::api::channel::Channel;
use crate::block_layout::FileLayout;

#[derive(Debug)]
/// High level representation of an MDF file.
///
/// The struct stores the memory mapped file internally and lazily exposes
/// [`ChannelGroup`] wrappers for easy inspection.
pub struct MDF {
    raw: MdfFile,
}

impl MDF {
    /// Parse an MDF4 file from disk.
    ///
    /// Not available on `wasm32-unknown-unknown`; use [`from_bytes`] instead.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_file(path: &str) -> Result<Self, MdfError> {
        let raw = MdfFile::parse_from_file(path)?;
        Ok(MDF { raw })
    }

    /// Parse an MDF4 file from an owned byte buffer.
    ///
    /// This is the primary entry point on `wasm32-unknown-unknown` where
    /// filesystem access is unavailable.  On native targets the caller can
    /// populate the buffer from `std::fs::read` or a memory-mapped file.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, MdfError> {
        let raw = MdfFile::parse_from_bytes(data)?;
        Ok(MDF { raw })
    }

    /// Retrieve channel groups contained in the file.
    ///
    /// Each [`ChannelGroup`] is created lazily and does not decode any samples.
    pub fn channel_groups(&self) -> Vec<ChannelGroup<'_>> {
        let mut groups = Vec::new();

        for raw_data_group in &self.raw.data_groups {
            for raw_channel_group in &raw_data_group.channel_groups {
                groups.push(ChannelGroup::new(
                    raw_data_group,
                    raw_channel_group,
                    &self.raw.mmap,
                ));
            }
        }

        groups
    }

    /// Find a channel group by name (first match).
    ///
    /// Convenience over [`MDF::channel_groups`] for the common case of
    /// addressing a group by its acquisition name.
    pub fn group(&self, name: &str) -> Option<ChannelGroup<'_>> {
        self.channel_groups()
            .into_iter()
            .find(|g| g.name().ok().flatten().as_deref() == Some(name))
    }

    /// Find a channel by name across all groups (first match).
    pub fn channel(&self, name: &str) -> Option<Channel<'_>> {
        for group in self.channel_groups() {
            for channel in group.channels() {
                if channel.name().ok().flatten().as_deref() == Some(name) {
                    return Some(channel);
                }
            }
        }
        None
    }

    /// Read a channel by name as a [`Signal`] (values paired with the master
    /// time axis of the channel's group). First match across all groups.
    ///
    /// Returns `Ok(None)` if no channel with that name exists.
    pub fn signal(&self, name: &str) -> Result<Option<crate::signal::Signal>, MdfError> {
        for group in self.channel_groups() {
            if let Some(sig) = group.signal(name)? {
                return Ok(Some(sig));
            }
        }
        Ok(None)
    }

    /// Read several channels in one pass per channel group — see
    /// [`ChannelGroup::signals_f64`](crate::api::channel_group::ChannelGroup::signals_f64).
    ///
    /// The result is index-aligned with `names` (`None` = channel not found
    /// anywhere). Each name resolves to its **first** match walking groups in
    /// file order, exactly like calling [`signal`](Self::signal) per name —
    /// but a group's data blocks are read (and inflated) at most once no
    /// matter how many of its channels are requested.
    pub fn signals_f64(
        &self,
        names: &[&str],
    ) -> Result<Vec<Option<crate::signal::SignalF64>>, MdfError> {
        let mut out: Vec<Option<crate::signal::SignalF64>> =
            names.iter().map(|_| None).collect();
        let mut remaining: Vec<usize> = (0..names.len()).collect();
        for group in self.channel_groups() {
            if remaining.is_empty() {
                break;
            }
            let want: Vec<&str> = remaining.iter().map(|&i| names[i]).collect();
            let got = group.signals_f64(&want)?;
            let mut still = Vec::new();
            for (k, sig) in got.into_iter().enumerate() {
                match sig {
                    Some(s) => out[remaining[k]] = Some(s),
                    None => still.push(remaining[k]),
                }
            }
            remaining = still;
        }
        Ok(out)
    }

    /// Get the start time of the measurement in nanoseconds since epoch.
    ///
    /// This is the absolute timestamp stored in the MDF file header.
    /// Returns None if the start time is 0 (not set).
    pub fn start_time_ns(&self) -> Option<u64> {
        let time = self.raw.header.abs_time;
        if time == 0 {
            None
        } else {
            Some(time)
        }
    }

    /// Build a [`FileLayout`] describing every block in the underlying file.
    ///
    /// The layout can be rendered as a flat table, an indented tree or JSON
    /// for inspecting on-disk structure and link chains.
    pub fn file_layout(&self) -> Result<FileLayout, MdfError> {
        FileLayout::from_bytes(&self.raw.mmap)
    }
}
