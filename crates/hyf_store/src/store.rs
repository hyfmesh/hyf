use core::fmt;

use hyf_core::{MessageId, TimestampMs};
use hyf_wire::{
    HyfEnvelopeRef, HyfWireError, decode_envelope, encode_envelope, envelope_encoded_len,
};

use crate::{StoreError, StorePolicy};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StoredFrameRef<'a> {
    pub message_id: MessageId,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: TimestampMs,
    pub bytes: &'a [u8],
}

impl<'a> StoredFrameRef<'a> {
    pub const fn new(
        message_id: MessageId,
        created_at_ms: TimestampMs,
        expires_at_ms: TimestampMs,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            message_id,
            created_at_ms,
            expires_at_ms,
            bytes,
        }
    }
}

impl fmt::Debug for StoredFrameRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredFrameRef")
            .field("message_id", &self.message_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct StoreRecord<const FRAME_MAX: usize> {
    bytes: [u8; FRAME_MAX],
    len: usize,
    message_id: MessageId,
    created_at_ms: TimestampMs,
    expires_at_ms: TimestampMs,
}

impl<const FRAME_MAX: usize> StoreRecord<FRAME_MAX> {
    fn new(frame: &[u8], metadata: StoreMetadata) -> Self {
        let mut bytes = [0; FRAME_MAX];
        bytes[..frame.len()].copy_from_slice(frame);
        Self {
            bytes,
            len: frame.len(),
            message_id: metadata.message_id,
            created_at_ms: metadata.created_at_ms,
            expires_at_ms: metadata.expires_at_ms,
        }
    }

    fn as_ref(&self) -> StoredFrameRef<'_> {
        StoredFrameRef::new(
            self.message_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.bytes[..self.len],
        )
    }
}

impl<const FRAME_MAX: usize> fmt::Debug for StoreRecord<FRAME_MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreRecord")
            .field("message_id", &self.message_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("bytes", &"<redacted>")
            .field("len", &self.len)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoreMetadata {
    message_id: MessageId,
    created_at_ms: TimestampMs,
    expires_at_ms: TimestampMs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store<const N: usize, const FRAME_MAX: usize> {
    policy: StorePolicy,
    records: [Option<StoreRecord<FRAME_MAX>>; N],
}

impl<const N: usize, const FRAME_MAX: usize> Store<N, FRAME_MAX> {
    pub const fn new(policy: StorePolicy) -> Self {
        Self {
            policy,
            records: [None; N],
        }
    }

    pub fn policy(&self) -> StorePolicy {
        self.policy
    }

    pub fn len(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        N
    }

    pub fn put_envelope(&mut self, envelope: HyfEnvelopeRef<'_>) -> Result<(), StoreError> {
        if self.policy.reject_expired_on_put && is_expired_at_creation(envelope) {
            return Err(StoreError::Expired);
        }
        let required = envelope_encoded_len(envelope).map_err(StoreError::InvalidEnvelope)?;
        if required > FRAME_MAX {
            return Err(StoreError::FrameTooLarge {
                actual: required,
                maximum: FRAME_MAX,
            });
        }

        let mut frame = [0; FRAME_MAX];
        let len = encode_envelope(envelope, &mut frame).map_err(StoreError::InvalidEnvelope)?;
        self.put_valid_frame(&frame[..len], metadata_for(envelope))
    }

    pub fn put_frame(&mut self, frame: &[u8]) -> Result<(), StoreError> {
        if frame.len() > FRAME_MAX {
            return Err(StoreError::FrameTooLarge {
                actual: frame.len(),
                maximum: FRAME_MAX,
            });
        }

        let envelope = decode_envelope(frame).map_err(|error| self.decode_error(error))?;
        self.put_valid_frame(frame, metadata_for(envelope))
    }

    pub fn remove(&mut self, message_id: MessageId) -> Result<(), StoreError> {
        let Some(index) = self.find_index(message_id) else {
            return Err(StoreError::NotFound);
        };
        self.records[index] = None;
        Ok(())
    }

    pub fn expire_before(&mut self, now: TimestampMs) -> usize {
        let mut removed = 0;
        for record in &mut self.records {
            if let Some(existing) = record
                && existing.expires_at_ms.0 <= now.0
            {
                *record = None;
                removed += 1;
            }
        }
        removed
    }

    pub fn pending<'a>(&'a self, out: &mut [StoredFrameRef<'a>]) -> Result<usize, StoreError> {
        let count = self.len();
        if out.len() < count {
            return Err(StoreError::OutputTooSmall {
                actual: out.len(),
                required: count,
            });
        }

        let mut written = 0;
        for record in self.records.iter().flatten() {
            insert_pending(out, written, record.as_ref());
            written += 1;
        }
        Ok(written)
    }

    pub fn first_pending(&self) -> Option<StoredFrameRef<'_>> {
        let mut selected: Option<usize> = None;
        for (index, record) in self.records.iter().enumerate() {
            let Some(record) = record else {
                continue;
            };
            selected = match selected {
                Some(existing) if !record_precedes(record, self.records[existing].as_ref()?) => {
                    Some(existing)
                }
                _ => Some(index),
            };
        }
        selected.and_then(|index| self.records[index].as_ref().map(StoreRecord::as_ref))
    }

    fn put_valid_frame(&mut self, frame: &[u8], metadata: StoreMetadata) -> Result<(), StoreError> {
        if self.contains(metadata.message_id) {
            return Err(StoreError::Duplicate);
        }
        let Some(index) = self.first_free_index() else {
            return Err(StoreError::Full);
        };

        self.records[index] = Some(StoreRecord::new(frame, metadata));
        Ok(())
    }

    fn contains(&self, message_id: MessageId) -> bool {
        self.find_index(message_id).is_some()
    }

    fn find_index(&self, message_id: MessageId) -> Option<usize> {
        for (index, record) in self.records.iter().enumerate() {
            if let Some(existing) = record
                && existing.message_id == message_id
            {
                return Some(index);
            }
        }
        None
    }

    fn first_free_index(&self) -> Option<usize> {
        self.records.iter().position(Option::is_none)
    }

    fn decode_error(&self, error: HyfWireError) -> StoreError {
        if self.policy.reject_expired_on_put && matches!(error, HyfWireError::InvalidExpiry) {
            StoreError::Expired
        } else {
            StoreError::InvalidEnvelope(error)
        }
    }
}

fn metadata_for(envelope: HyfEnvelopeRef<'_>) -> StoreMetadata {
    StoreMetadata {
        message_id: envelope.message_id,
        created_at_ms: envelope.created_at_ms,
        expires_at_ms: envelope.expires_at_ms,
    }
}

fn is_expired_at_creation(envelope: HyfEnvelopeRef<'_>) -> bool {
    envelope.expires_at_ms.0 <= envelope.created_at_ms.0
}

fn insert_pending<'a>(out: &mut [StoredFrameRef<'a>], written: usize, record: StoredFrameRef<'a>) {
    let mut index = written;
    while index > 0 && frame_precedes(record, out[index - 1]) {
        out[index] = out[index - 1];
        index -= 1;
    }
    out[index] = record;
}

fn record_precedes<const FRAME_MAX: usize>(
    record: &StoreRecord<FRAME_MAX>,
    existing: &StoreRecord<FRAME_MAX>,
) -> bool {
    record.expires_at_ms.0 < existing.expires_at_ms.0
        || (record.expires_at_ms.0 == existing.expires_at_ms.0
            && record.created_at_ms.0 < existing.created_at_ms.0)
        || (record.expires_at_ms.0 == existing.expires_at_ms.0
            && record.created_at_ms.0 == existing.created_at_ms.0
            && record.message_id.0 < existing.message_id.0)
}

fn frame_precedes(record: StoredFrameRef<'_>, existing: StoredFrameRef<'_>) -> bool {
    record.expires_at_ms.0 < existing.expires_at_ms.0
        || (record.expires_at_ms.0 == existing.expires_at_ms.0
            && record.created_at_ms.0 < existing.created_at_ms.0)
        || (record.expires_at_ms.0 == existing.expires_at_ms.0
            && record.created_at_ms.0 == existing.created_at_ms.0
            && record.message_id.0 < existing.message_id.0)
}

#[cfg(test)]
pub(crate) mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{
        HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, HyfWireError, PayloadKind,
        decode_envelope, encode_envelope,
    };

    use super::{Store, StoredFrameRef};
    use crate::{StoreError, StorePolicy};

    #[test]
    fn store_owns_encoded_frames_and_lists_pending() -> Result<(), StoreError> {
        let mut store = Store::<2, 128>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 300, b"one");
        let second = sample_envelope(MessageId([2; 32]), 100, 200, b"two");
        let mut pending = [empty_stored_frame(); 2];

        store.put_envelope(first)?;
        store.put_envelope(second)?;
        let count = store.pending(&mut pending)?;

        assert_eq!(count, 2);
        assert_eq!(pending[0].message_id, MessageId([2; 32]));
        assert_eq!(pending[1].message_id, MessageId([1; 32]));
        assert_eq!(decode_envelope(pending[0].bytes)?.payload, b"two");
        assert_eq!(decode_envelope(pending[1].bytes)?.payload, b"one");
        Ok(())
    }

    #[test]
    fn put_frame_copies_input_bytes() -> Result<(), StoreError> {
        let mut store = Store::<1, 128>::new(StorePolicy::new());
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, b"owned");
        let mut frame = [0; 128];
        let len = encode_envelope(envelope, &mut frame).map_err(StoreError::InvalidEnvelope)?;

        store.put_frame(&frame[..len])?;
        frame[..len].fill(0);

        let stored = store.first_pending().ok_or(StoreError::NotFound)?;
        assert_eq!(decode_envelope(stored.bytes)?.payload, b"owned");
        Ok(())
    }

    #[test]
    fn store_rejects_duplicate_expired_invalid_oversized_and_full_inputs() -> Result<(), StoreError>
    {
        let mut store = Store::<1, 128>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 200, b"one");
        let duplicate = sample_envelope(MessageId([1; 32]), 100, 300, b"dupe");
        let expired = sample_envelope(MessageId([2; 32]), 100, 100, b"expired");
        let overflow = sample_envelope(MessageId([3; 32]), 100, 400, b"overflow");
        let invalid = [0xff, 0x00];
        let oversized = [0u8; 129];

        store.put_envelope(first)?;
        assert_eq!(store.put_envelope(duplicate), Err(StoreError::Duplicate));
        assert_eq!(store.put_envelope(expired), Err(StoreError::Expired));
        assert!(matches!(
            store.put_frame(&invalid),
            Err(StoreError::InvalidEnvelope(_))
        ));
        assert_eq!(
            store.put_frame(&oversized),
            Err(StoreError::FrameTooLarge {
                actual: 129,
                maximum: 128,
            })
        );
        assert_eq!(store.put_envelope(overflow), Err(StoreError::Full));
        Ok(())
    }

    #[test]
    fn put_envelope_reports_oversized_encoded_frame() {
        let mut store = Store::<1, 16>::new(StorePolicy::new());
        let envelope = sample_envelope(MessageId([1; 32]), 100, 200, b"too large");

        assert!(matches!(
            store.put_envelope(envelope),
            Err(StoreError::FrameTooLarge {
                actual,
                maximum: 16,
            }) if actual > 16
        ));
    }

    #[test]
    fn store_removes_existing_messages_and_reports_missing() -> Result<(), StoreError> {
        let mut store = Store::<2, 128>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 200, b"one");

        store.put_envelope(first)?;
        assert_eq!(store.len(), 1);
        store.remove(MessageId([1; 32]))?;
        assert!(store.is_empty());
        assert_eq!(store.remove(MessageId([1; 32])), Err(StoreError::NotFound));
        Ok(())
    }

    #[test]
    fn store_expires_by_timestamp() -> Result<(), StoreError> {
        let mut store = Store::<3, 128>::new(StorePolicy::new());
        store.put_envelope(sample_envelope(MessageId([1; 32]), 100, 200, b"one"))?;
        store.put_envelope(sample_envelope(MessageId([2; 32]), 100, 300, b"two"))?;
        store.put_envelope(sample_envelope(MessageId([3; 32]), 100, 400, b"three"))?;

        assert_eq!(store.expire_before(TimestampMs(300)), 2);
        assert_eq!(store.len(), 1);
        assert_eq!(store.expire_before(TimestampMs(300)), 0);
        Ok(())
    }

    #[test]
    fn pending_reports_short_output_before_writing_all_records() -> Result<(), StoreError> {
        let mut store = Store::<2, 128>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 200, b"one");
        let second = sample_envelope(MessageId([2; 32]), 100, 300, b"two");
        let mut pending = [empty_stored_frame(); 1];

        store.put_envelope(first)?;
        store.put_envelope(second)?;

        assert_eq!(
            store.pending(&mut pending),
            Err(StoreError::OutputTooSmall {
                actual: 1,
                required: 2,
            })
        );
        assert_eq!(pending[0].message_id, MessageId([0; 32]));
        Ok(())
    }

    #[test]
    fn pending_order_uses_expiry_created_at_and_message_id() -> Result<(), StoreError> {
        let mut store = Store::<3, 128>::new(StorePolicy::new());
        let high_id = sample_envelope(MessageId([9; 32]), 100, 200, b"high");
        let low_id = sample_envelope(MessageId([1; 32]), 100, 200, b"low");
        let older = sample_envelope(MessageId([5; 32]), 90, 200, b"older");
        let mut pending = [empty_stored_frame(); 3];

        store.put_envelope(high_id)?;
        store.put_envelope(low_id)?;
        store.put_envelope(older)?;
        store.pending(&mut pending)?;

        assert_eq!(pending[0].message_id, MessageId([5; 32]));
        assert_eq!(pending[1].message_id, MessageId([1; 32]));
        assert_eq!(pending[2].message_id, MessageId([9; 32]));
        Ok(())
    }

    #[test]
    fn first_pending_returns_lowest_deterministic_record() -> Result<(), StoreError> {
        let mut store = Store::<3, 128>::new(StorePolicy::new());
        let high_id = sample_envelope(MessageId([9; 32]), 100, 200, b"high");
        let low_id = sample_envelope(MessageId([1; 32]), 100, 200, b"low");

        store.put_envelope(high_id)?;
        store.put_envelope(low_id)?;

        assert_eq!(
            store.first_pending().map(|stored| stored.message_id),
            Some(MessageId([1; 32]))
        );
        Ok(())
    }

    #[test]
    fn stored_frame_debug_redacts_bytes() -> Result<(), StoreError> {
        let mut store = Store::<1, 128>::new(StorePolicy::new());
        store.put_envelope(sample_envelope(MessageId([1; 32]), 100, 200, b"secret"))?;
        let stored = store.first_pending().ok_or(StoreError::NotFound)?;
        let stored_debug = format!("{stored:?}");
        let store_debug = format!("{store:?}");

        assert!(stored_debug.contains("<redacted>"));
        assert!(store_debug.contains("<redacted>"));
        assert!(!stored_debug.contains("secret"));
        assert!(!store_debug.contains("secret"));
        assert!(!stored_debug.contains("115, 101, 99"));
        assert!(!store_debug.contains("115, 101, 99"));
        Ok(())
    }

    fn empty_stored_frame() -> StoredFrameRef<'static> {
        StoredFrameRef::new(MessageId([0; 32]), TimestampMs(0), TimestampMs(1), b"")
    }

    pub(crate) fn sample_envelope<'a>(
        message_id: MessageId,
        created_at_ms: u64,
        expires_at_ms: u64,
        payload: &'a [u8],
    ) -> HyfEnvelopeRef<'a> {
        HyfEnvelopeRef {
            version: HYF_WIRE_VERSION_0,
            message_id,
            source: NodeId([0x22; 32]),
            destination: HyfDestination::Node(NodeId([0x44; 32])),
            created_at_ms: TimestampMs(created_at_ms),
            expires_at_ms: TimestampMs(expires_at_ms),
            hop_limit: 9,
            payload_kind: PayloadKind::HyfNativeV0,
            payload,
        }
    }

    impl From<HyfWireError> for StoreError {
        fn from(error: HyfWireError) -> Self {
            StoreError::InvalidEnvelope(error)
        }
    }
}
