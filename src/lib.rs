//! Filtering and byte-chunking of DBN record streams, as a downstream wrapper
//! over [`dbn`](https://crates.io/crates/dbn).
//!
//! [`ByteChunker`] owns a [`dbn::decode::dbn::fsm::DbnFsm`] and a reader
//! directly and uses [`DbnFsm::process_many`] to batch-decode records. It
//! accepts header-filter configuration (`instrument_ids`, `publisher_ids`,
//! `start_ts` / `end_ts`) and yields bounded-size [`ByteChunk`]s of raw
//! record bytes.
//!
//! Output bytes follow the FSM's [`dbn::VersionUpgradePolicy`]; filters are
//! ANDed with the same semantics as the `dbn` Python/R/Ruby filter APIs.
//!
//! # Example
//!
//! ```ignore
//! use dbn::VersionUpgradePolicy;
//! use dbn::decode::DynReader;
//! use dbn::encode::DbnMetadataEncoder;
//! use dbn_chunks::ByteChunker;
//!
//! let reader = DynReader::from_file("20241007.dbn.zst")?;
//! let mut chunker = ByteChunker::with_upgrade_policy(reader, VersionUpgradePolicy::UpgradeToV3)?
//!     .with_instrument_ids([123_456]);
//! let mut out: Vec<u8> = Vec::new();
//! while let Some(chunk) = chunker.next_chunk()? {
//!     out.extend_from_slice(chunk.bytes());
//! }
//! # Ok::<(), dbn::Error>(())
//! ```

use dbn::{Record, RecordBuf, RecordRef};

mod chunker;
pub use chunker::{ByteChunk, ByteChunker, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS};

/// Decision produced by [`FilterState::classify`] for a single record.
pub(crate) enum Classification {
    Emit,
    DropTime,
    DropInstrument,
    DropPublisher,
    End,
}

pub(crate) struct FilterState {
    pub start_ts: Option<u64>,
    pub end_ts: Option<u64>,
    // Empty `Vec` means "no filter". Vec rather than `Option<Vec>` so the
    // unfiltered default doesn't allocate.
    pub instrument_ids: Vec<u32>,
    pub publisher_ids: Vec<u16>,
    // Latched: set once when `end_ts` trips and never cleared; the chunker
    // also flips its own `done` flag in the same pass so no later record can
    // overwrite it.
    pub tripping_record: Option<RecordBuf>,
    pub records_emitted: u64,
    pub records_dropped_by_time: u64,
    pub records_dropped_by_instrument_id: u64,
    pub records_dropped_by_publisher_id: u64,
}

impl FilterState {
    pub(crate) fn passes_instrument(&self, id: u32) -> bool {
        self.instrument_ids.is_empty() || self.instrument_ids.contains(&id)
    }

    pub(crate) fn passes_publisher(&self, id: u16) -> bool {
        self.publisher_ids.is_empty() || self.publisher_ids.contains(&id)
    }

    /// Classifies `rec` against every filter, updating the drop counters and
    /// the tripping-record slot as a side effect.
    pub(crate) fn classify(&mut self, rec: RecordRef<'_>) -> Classification {
        let primary_ts = rec.raw_index_ts();
        let hd = rec.header();

        if let Some(end) = self.end_ts
            && primary_ts >= end
        {
            // Only stash the tripping record if it would have passed the
            // header filters, otherwise a filtered-out record could leak
            // into a resumed stream via the inner decoder.
            if self.passes_instrument(hd.instrument_id) && self.passes_publisher(hd.publisher_id) {
                self.tripping_record = Some(rec.to_owned());
            }
            return Classification::End;
        }
        if let Some(start) = self.start_ts
            && primary_ts < start
        {
            self.records_dropped_by_time += 1;
            return Classification::DropTime;
        }
        if !self.passes_instrument(hd.instrument_id) {
            self.records_dropped_by_instrument_id += 1;
            return Classification::DropInstrument;
        }
        if !self.passes_publisher(hd.publisher_id) {
            self.records_dropped_by_publisher_id += 1;
            return Classification::DropPublisher;
        }

        self.records_emitted += 1;
        Classification::Emit
    }
}

/// Emit/drop counters for a [`ByteChunker`]. Returned by
/// [`ByteChunker::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FilterStats {
    /// Records that passed every filter.
    pub emitted: u64,
    /// Records dropped because their primary timestamp was below `start_ts`.
    /// The `end_ts` tripping record is not counted here.
    pub dropped_by_time: u64,
    /// Records dropped because their `instrument_id` was not in the configured
    /// allow-list.
    pub dropped_by_instrument_id: u64,
    /// Records dropped because their `publisher_id` was not in the configured
    /// allow-list.
    pub dropped_by_publisher_id: u64,
}
