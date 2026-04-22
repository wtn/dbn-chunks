//! [`ByteChunker`]: aggregates records from a DBN stream into bounded
//! byte chunks, using [`DbnFsm::process_many`] to batch record decoding and
//! applying header filters inline.
//!
//! Output bytes follow the FSM's [`VersionUpgradePolicy`]; filters are ANDed
//! (`instrument_ids`, `publisher_ids`, and the half-open window
//! `[start_ts, end_ts)`). Terminal decode errors are latched and subsequent
//! `next_chunk` calls return `Ok(None)` without touching the reader.

use std::{
    fmt,
    io::{self, Read},
    num::NonZeroUsize,
};

use dbn::{
    Metadata, RecordBuf, RecordRef, VersionUpgradePolicy,
    decode::dbn::fsm::{DbnFsm, ProcessResult},
};

use crate::{Classification, FilterState, FilterStats};

/// Number of record refs decoded per `process_many` batch. Sized for a few
/// cache lines of `RecordRef`s; picked to keep per-batch overhead well under
/// the per-record body cost.
const BATCH: usize = 256;

/// One chunk of DBN record bytes yielded by an [`ByteChunker`].
///
/// The slice returned by [`bytes`](Self::bytes) borrows the chunker's internal
/// buffer and is valid until the next `next_chunk` call.
pub struct ByteChunk<'a> {
    bytes: &'a [u8],
    count: u64,
}

impl<'a> ByteChunk<'a> {
    /// Concatenated raw bytes of one or more DBN records that passed filters.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Number of records contained in [`bytes`](Self::bytes).
    pub fn count(&self) -> u64 {
        self.count
    }
}

impl fmt::Debug for ByteChunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteChunk")
            .field("count", &self.count)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Chunker that owns a [`DbnFsm`] and a reader directly. Use
/// [`with_upgrade_policy`](Self::with_upgrade_policy) to pick the decoder
/// policy, then builder-style setters for chunk sizing and filters.
pub struct ByteChunker<R> {
    reader: R,
    fsm: DbnFsm,
    metadata: Option<Metadata>,
    max_records: NonZeroUsize,
    max_bytes: NonZeroUsize,
    buf: Vec<u8>,
    filter: FilterState,
    // Set once on `Classification::End`, terminal decode error, or reader EOF
    // after all buffered records are drained. Subsequent calls short-circuit.
    done: bool,
    // Set when `reader.read()` returns 0; lets us distinguish "need more data"
    // from "end of input" when `process_many` returns an empty batch.
    reader_eof: bool,
}

/// The default soft byte ceiling for each chunk, 4 MiB. Sized to give a
/// predictable peak buffer size across schemas; across DBN record sizes this
/// buffers anywhere from roughly 11k [`dbn::Mbp10Msg`] to 75k [`dbn::MboMsg`]
/// per chunk.
pub const DEFAULT_MAX_BYTES: NonZeroUsize = match NonZeroUsize::new(4 * 1024 * 1024) {
    Some(n) => n,
    None => unreachable!(),
};

/// Default records-per-chunk ceiling. Bounds the active slice passed to
/// `process_many` across the batching loop; 65_536 matches the batch size
/// used by `dbn-ruby`.
pub const DEFAULT_MAX_RECORDS: NonZeroUsize = match NonZeroUsize::new(65_536) {
    Some(n) => n,
    None => unreachable!(),
};

impl<R> ByteChunker<R> {
    /// Sets a hard record-count ceiling per chunk.
    pub fn with_max_records(mut self, n: NonZeroUsize) -> Self {
        self.max_records = n;
        self
    }

    /// Sets a soft byte ceiling per chunk. Once the running chunk reaches or
    /// exceeds this size, the chunk is closed.
    pub fn with_max_bytes(mut self, n: NonZeroUsize) -> Self {
        self.max_bytes = n;
        self
    }

    /// Restricts output to records whose `instrument_id` is in `ids`. An
    /// empty iterator means no filter. Calling again replaces the previous
    /// list rather than extending it.
    ///
    /// Filters are matched with `Vec::contains`, which is faster than a
    /// `HashSet` lookup at the list sizes this API is designed for (on the
    /// order of tens of ids). Callers filtering against thousands of ids
    /// should pre-filter upstream.
    pub fn with_instrument_ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = u32>,
    {
        self.filter.instrument_ids = ids.into_iter().collect();
        self
    }

    /// Restricts output to records whose `publisher_id` is in `ids`. Accepts
    /// any iterator whose items can be converted to `u16`, so either raw ids
    /// or [`dbn::Publisher`] values work. An empty iterator means no filter.
    /// See [`with_instrument_ids`](Self::with_instrument_ids) for notes on
    /// filter-list sizing.
    pub fn with_publisher_ids<I, P>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<u16>,
    {
        self.filter.publisher_ids = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Lower bound of the half-open time window `[start_ts, end_ts)`. Skips
    /// records whose primary timestamp is less than `start_ts`. The primary
    /// timestamp is [`dbn::Record::raw_index_ts`], which matches the sort
    /// order of DBN files: `ts_recv` for every schema that carries it (MBO,
    /// MBP, trades, BBO, CMBP, CBBO, status, etc.), with a fallback to
    /// `ts_event` for schemas without a `ts_recv` field.
    pub fn with_start_ts(mut self, start_ts: u64) -> Self {
        self.filter.start_ts = Some(start_ts);
        self
    }

    /// Upper bound of the half-open time window `[start_ts, end_ts)`.
    /// Terminates iteration at the first record whose primary timestamp is
    /// at or past `end_ts`. The tripping record is consumed from the decoder
    /// and *not* emitted; if it would have passed the other header filters
    /// it is stashed on the chunker (see
    /// [`tripping_record`](Self::tripping_record)), otherwise it is dropped.
    ///
    /// Early termination requires the input to be monotonically non-decreasing
    /// in the primary timestamp. DBN files produced by the Databento API
    /// satisfy this; custom inputs that re-sort by a different field will
    /// silently drop records past the first trip.
    pub fn with_end_ts(mut self, end_ts: u64) -> Self {
        self.filter.end_ts = Some(end_ts);
        self
    }

    /// Returns the DBN metadata once it has been decoded. `None` until the
    /// first `next_chunk` call produces (or skips past) the metadata header.
    pub fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }

    /// Returns the stashed tripping record, if any (only populated when
    /// iteration terminated on `end_ts`).
    pub fn tripping_record(&self) -> Option<&RecordBuf> {
        self.filter.tripping_record.as_ref()
    }

    /// Snapshot of the filter counters.
    pub fn stats(&self) -> FilterStats {
        FilterStats {
            emitted: self.filter.records_emitted,
            dropped_by_time: self.filter.records_dropped_by_time,
            dropped_by_instrument_id: self.filter.records_dropped_by_instrument_id,
            dropped_by_publisher_id: self.filter.records_dropped_by_publisher_id,
        }
    }
}

impl<R: Read> ByteChunker<R> {
    /// Builds a chunker using [`VersionUpgradePolicy::AsIs`] (output bytes ==
    /// input bytes). Suitable for current-version DBN data where no upgrade
    /// is required.
    pub fn new(reader: R) -> dbn::Result<Self> {
        Self::with_upgrade_policy(reader, VersionUpgradePolicy::AsIs)
    }

    /// Builds a chunker with the given [`VersionUpgradePolicy`]. Output bytes
    /// reflect whatever the FSM produces (upgraded layout when the policy
    /// triggers an upgrade).
    pub fn with_upgrade_policy(reader: R, upgrade_policy: VersionUpgradePolicy) -> dbn::Result<Self> {
        let fsm = DbnFsm::builder().upgrade_policy(upgrade_policy).build()?;
        Ok(Self {
            reader,
            fsm,
            metadata: None,
            max_records: DEFAULT_MAX_RECORDS,
            max_bytes: DEFAULT_MAX_BYTES,
            buf: Vec::new(),
            filter: FilterState {
                start_ts: None,
                end_ts: None,
                instrument_ids: Vec::new(),
                publisher_ids: Vec::new(),
                tripping_record: None,
                records_emitted: 0,
                records_dropped_by_time: 0,
                records_dropped_by_instrument_id: 0,
                records_dropped_by_publisher_id: 0,
            },
            done: false,
            reader_eof: false,
        })
    }

    /// Pulls records from the reader until a chunk is full, the filter's
    /// `end_ts` trips, the reader is exhausted, or a terminal error occurs.
    /// Returns `Ok(None)` when there are no more records to emit.
    ///
    /// # Errors
    /// Returns a decode or I/O error on the first call where the underlying
    /// FSM or reader fails. Errors are terminal: any in-progress chunk is
    /// dropped and later calls return `Ok(None)` without reading.
    pub fn next_chunk(&mut self) -> dbn::Result<Option<ByteChunk<'_>>> {
        if self.done {
            return Ok(None);
        }
        self.buf.clear();
        let mut count: usize = 0;

        // Destructure so `buf`, `filter`, `fsm`, `reader` are independently
        // borrowable inside the batching loop.
        let Self {
            reader,
            fsm,
            metadata,
            max_records,
            max_bytes,
            buf,
            filter,
            done,
            reader_eof,
            ..
        } = self;

        'outer: loop {
            let remaining = max_records.get() - count;
            if remaining == 0 {
                break;
            }
            if buf.len() >= max_bytes.get() {
                break;
            }

            // `slots` MUST be declared inside the loop so its fresh lifetime
            // can re-bind to each `&mut fsm` borrow. Limit the active slice to
            // `remaining` so `process_many` can't consume more records than
            // the chunk is allowed to hold; once the FSM has moved past a
            // record, the chunker has no way to give it back.
            let mut slots: [Option<RecordRef<'_>>; BATCH] = [const { None }; BATCH];
            let active = remaining.min(BATCH);
            match fsm.process_many(&mut slots[..active]) {
                ProcessResult::Record(refs) => {
                    if refs.is_empty() {
                        // Either the buffer has a partial record and we need
                        // more bytes, or the reader is exhausted and we're done.
                        if *reader_eof {
                            *done = true;
                            break;
                        }
                        match reader.read(fsm.space()) {
                            Ok(0) => {
                                *reader_eof = true;
                                continue;
                            }
                            Ok(n) => fsm.fill(n),
                            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                                *reader_eof = true;
                                continue;
                            }
                            Err(err) => {
                                *done = true;
                                return Err(dbn::Error::io(err, "fsm_chunker reading bytes"));
                            }
                        }
                        continue;
                    }
                    for r in refs.iter() {
                        match filter.classify(*r) {
                            Classification::Emit => {
                                buf.extend_from_slice(r.as_ref());
                                count += 1;
                            }
                            Classification::End => {
                                *done = true;
                                break 'outer;
                            }
                            Classification::DropTime
                            | Classification::DropInstrument
                            | Classification::DropPublisher => continue,
                        }
                    }
                }
                ProcessResult::ReadMore(_) => {
                    if *reader_eof {
                        *done = true;
                        break;
                    }
                    match reader.read(fsm.space()) {
                        Ok(0) => {
                            *reader_eof = true;
                            continue;
                        }
                        Ok(n) => fsm.fill(n),
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                            *reader_eof = true;
                            continue;
                        }
                        Err(err) => {
                            *done = true;
                            return Err(dbn::Error::io(err, "fsm_chunker reading bytes"));
                        }
                    }
                }
                ProcessResult::Metadata(m) => {
                    *metadata = Some(m);
                    // Continue: metadata is emitted once; subsequent calls
                    // will go straight to Record state.
                }
                ProcessResult::Err(e) => {
                    *done = true;
                    return Err(e);
                }
            }
        }

        if count == 0 {
            return Ok(None);
        }
        Ok(Some(ByteChunk {
            bytes: &self.buf,
            count: count as u64,
        }))
    }
}

impl<R> fmt::Debug for ByteChunker<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteChunker")
            .field("max_records", &self.max_records)
            .field("max_bytes", &self.max_bytes)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbn::{
        Dataset, MboMsg, Mbp1Msg, RecordHeader, SType, Schema, SymbolMapping, TradeMsg, rtype,
    };
    use dbn::encode::{DbnMetadataEncoder, DbnRecordEncoder, EncodeRecord};
    use std::io::Cursor;

    fn mbo(instrument_id: u32, publisher_id: u16, ts_event: u64) -> MboMsg {
        MboMsg {
            hd: RecordHeader::new::<MboMsg>(rtype::MBO, publisher_id, instrument_id, ts_event),
            ts_recv: ts_event,
            ..Default::default()
        }
    }

    fn mbp1(instrument_id: u32, ts_event: u64, ts_recv: u64) -> Mbp1Msg {
        Mbp1Msg {
            hd: RecordHeader::new::<Mbp1Msg>(rtype::MBP_1, 1, instrument_id, ts_event),
            ts_recv,
            ..Default::default()
        }
    }

    fn encode_with_metadata<T: dbn::encode::DbnEncodable>(recs: &[T]) -> Vec<u8> {
        let mut data = Vec::new();
        let metadata = Metadata::builder()
            .version(dbn::DBN_VERSION)
            .dataset(Dataset::XnasItch)
            .schema(Some(Schema::Mbo))
            .stype_in(Some(SType::RawSymbol))
            .stype_out(SType::InstrumentId)
            .start(0)
            .symbols(Vec::<String>::new())
            .mappings(Vec::<SymbolMapping>::new())
            .build();
        let mut enc = DbnMetadataEncoder::new(&mut data);
        enc.encode(&metadata).unwrap();
        drop(enc);
        let mut enc = DbnRecordEncoder::new(&mut data);
        for r in recs {
            enc.encode_record(r).unwrap();
        }
        data
    }

    fn drain<R: Read>(chunker: &mut ByteChunker<R>) -> dbn::Result<(Vec<u8>, u64)> {
        let mut all = Vec::new();
        let mut total = 0u64;
        while let Some(c) = chunker.next_chunk()? {
            all.extend_from_slice(c.bytes());
            total += c.count();
        }
        Ok((all, total))
    }

    #[test]
    fn round_trip_verbatim() {
        let recs = vec![mbo(1, 10, 100), mbo(2, 10, 200), mbo(3, 20, 300)];
        let expected_records: Vec<u8> = recs
            .iter()
            .flat_map(|r| AsRef::<[u8]>::as_ref(r).to_vec())
            .collect();
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data)).unwrap();
        let (out, count) = drain(&mut chunker).unwrap();
        assert_eq!(count, 3);
        assert_eq!(out, expected_records);
        assert!(chunker.metadata().is_some());
    }

    #[test]
    fn filter_by_instrument_id() {
        let recs = vec![mbo(1, 10, 100), mbo(2, 10, 200), mbo(1, 10, 300)];
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data))
            .unwrap()
            .with_instrument_ids([1]);
        let (_out, count) = drain(&mut chunker).unwrap();
        assert_eq!(count, 2);
        assert_eq!(chunker.stats().dropped_by_instrument_id, 1);
    }

    #[test]
    fn filter_by_publisher_id() {
        let recs = vec![mbo(1, 10, 100), mbo(2, 20, 200), mbo(3, 10, 300)];
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data))
            .unwrap()
            .with_publisher_ids([20u16]);
        let (_out, count) = drain(&mut chunker).unwrap();
        assert_eq!(count, 1);
        assert_eq!(chunker.stats().dropped_by_publisher_id, 2);
    }

    #[test]
    fn filter_time_window_uses_ts_recv_for_mbp() {
        let recs = vec![
            mbp1(1, 90, 100),
            mbp1(1, 180, 200),
            mbp1(1, 280, 300),
            mbp1(1, 380, 400),
        ];
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data))
            .unwrap()
            .with_start_ts(150)
            .with_end_ts(350);
        let (_out, count) = drain(&mut chunker).unwrap();
        assert_eq!(count, 2);
        assert_eq!(chunker.stats().emitted, 2);
        assert_eq!(chunker.stats().dropped_by_time, 1);
    }

    #[test]
    fn end_ts_stashes_tripping_record() {
        let recs = vec![mbo(1, 10, 100), mbo(1, 10, 300), mbo(1, 10, 400)];
        let expected_trip: Vec<u8> = AsRef::<[u8]>::as_ref(&recs[1]).to_vec();
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data))
            .unwrap()
            .with_end_ts(250);
        let (_out, count) = drain(&mut chunker).unwrap();
        assert_eq!(count, 1);
        let trip = chunker.tripping_record().expect("stashed");
        assert_eq!(AsRef::<[u8]>::as_ref(trip), expected_trip.as_slice());
    }

    #[test]
    fn max_records_splits_chunks() {
        let recs: Vec<_> = (0..10).map(|i| mbo(1, 10, i)).collect();
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data))
            .unwrap()
            .with_max_records(NonZeroUsize::new(4).unwrap());
        let mut sizes = Vec::new();
        while let Some(c) = chunker.next_chunk().unwrap() {
            sizes.push(c.count());
        }
        assert_eq!(sizes, vec![4u64, 4, 2]);
    }

    #[test]
    fn max_bytes_splits_chunks() {
        // max_bytes is enforced at batch granularity (not per-record), so
        // set max_records low enough that one batch can't exceed it and
        // check that the byte bound drives the split.
        let recs: Vec<_> = (0..20).map(|i| mbo(1, 10, i)).collect();
        let rec_size = std::mem::size_of::<MboMsg>();
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data))
            .unwrap()
            .with_max_records(NonZeroUsize::new(4).unwrap())
            .with_max_bytes(NonZeroUsize::new(rec_size * 2).unwrap());
        let mut sizes = Vec::new();
        while let Some(c) = chunker.next_chunk().unwrap() {
            sizes.push(c.count());
        }
        // Each chunk closes when buf.len() >= max_bytes; with max_records=4
        // and max_bytes=2*rec_size, the first batch fills to 4 records (past
        // the byte bound), closes, and the loop repeats.
        assert_eq!(sizes, vec![4u64, 4, 4, 4, 4]);
    }

    #[test]
    fn idempotent_after_drain() {
        let recs = vec![mbo(1, 10, 100), mbo(1, 10, 200)];
        let data = encode_with_metadata(&recs);
        let mut chunker = ByteChunker::new(Cursor::new(data)).unwrap();
        while chunker.next_chunk().unwrap().is_some() {}
        assert!(chunker.next_chunk().unwrap().is_none());
        assert!(chunker.next_chunk().unwrap().is_none());
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        let data: Vec<u8> = encode_with_metadata::<MboMsg>(&[]);
        let mut chunker = ByteChunker::new(Cursor::new(data)).unwrap();
        assert!(chunker.next_chunk().unwrap().is_none());
    }

    #[test]
    fn upgrade_v1_to_v3_trade_survives_chunking() {
        // Encode v1 metadata + trades, chunk with UpgradeToV3, confirm the
        // output is valid when metadata is encoded ahead of it.
        let v1_meta = Metadata::builder()
            .version(1)
            .dataset(Dataset::XnasItch)
            .schema(Some(Schema::Trades))
            .stype_in(Some(SType::RawSymbol))
            .stype_out(SType::InstrumentId)
            .start(0)
            .symbols(Vec::<String>::new())
            .mappings(Vec::<SymbolMapping>::new())
            .build();
        let mut data = Vec::new();
        DbnMetadataEncoder::new(&mut data).encode(&v1_meta).unwrap();
        let mut enc = DbnRecordEncoder::new(&mut data);
        for _ in 0..3 {
            enc.encode_record(&TradeMsg::default()).unwrap();
        }
        drop(enc);
        let mut chunker = ByteChunker::with_upgrade_policy(
            Cursor::new(data),
            VersionUpgradePolicy::UpgradeToV3,
        )
        .unwrap();
        let (_, count) = drain(&mut chunker).unwrap();
        assert_eq!(count, 3);
        let m = chunker.metadata().expect("decoded");
        assert_eq!(m.version, 3);
    }
}
