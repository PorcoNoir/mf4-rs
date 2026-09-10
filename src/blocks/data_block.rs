use crate::blocks::common::BlockHeader;
use crate::blocks::common::BlockParse;
use crate::error::MdfError;
use std::borrow::Cow;

#[derive(Debug)]
pub struct DataBlock<'a> {
    pub header: BlockHeader,
    /// Borrowed straight from the mmap for plain `##DT`/`##DV` blocks;
    /// owned when the payload was inflated out of a compressed `##DZ`.
    pub data: Cow<'a, [u8]>,
}

impl<'a> BlockParse<'a> for DataBlock<'a> {
    const ID: &'static str = "##DT";
    /// Parse a DTBLOCK or DVBLOCK from the given byte slice.
    ///
    /// Both `##DT` (record data) and `##DV` (sample data of a column-oriented
    /// group) blocks share the same layout: a 24-byte header followed by raw
    /// data. Any other block id is rejected.
    ///
    /// The slice must contain at least the number of bytes specified by the
    /// block length in the header. Only a reference to the data portion is
    /// stored to avoid unnecessary allocations.
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, MdfError> {

        let header = BlockHeader::from_bytes(bytes)?;
        if header.id != "##DT" && header.id != "##DV" {
            return Err(MdfError::BlockIDError {
                actual: header.id.clone(),
                expected: "##DT / ##DV".to_string(),
            });
        }

        let data_len = (header.block_len as usize).saturating_sub(24);
        let expected_bytes = 24 + data_len;
        if bytes.len() < expected_bytes {
            return Err(MdfError::TooShortBuffer {
                actual:   bytes.len(),
                expected: expected_bytes,
                file:     file!(),
                line:     line!(),
            });
        }
        let data = Cow::Borrowed(&bytes[24..24 + data_len]);
        Ok(Self { header, data })
    }
}
impl<'a> DataBlock<'a> {
    /// A block whose payload was produced by decompression (`##DZ`).
    pub fn from_owned(header: BlockHeader, data: Vec<u8>) -> Self {
        Self {
            header,
            data: Cow::Owned(data),
        }
    }

    /// Iterate over raw records of fixed size.
    /// If the data block contains padding at the end, it’s your caller’s responsibility to trim that.
    ///
    /// # Arguments
    /// * `record_size` - Size in bytes of one record (including record ID)
    ///
    /// # Returns
    /// An iterator yielding each raw record slice.
    pub fn records(&self, record_size: usize) -> impl Iterator<Item = &[u8]> {
        self.data.chunks_exact(record_size)
    }
}
