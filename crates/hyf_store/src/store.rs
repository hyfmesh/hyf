use hyf_core::{MessageId, TimestampMs};
use hyf_wire::HyfEnvelopeRef;

use crate::{StoreError, StorePolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredEnvelopeRef<'a> {
    pub envelope: HyfEnvelopeRef<'a>,
}

impl<'a> StoredEnvelopeRef<'a> {
    pub const fn new(envelope: HyfEnvelopeRef<'a>) -> Self {
        Self { envelope }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoreRecord<'a> {
    envelope: HyfEnvelopeRef<'a>,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store<'a, const N: usize> {
    policy: StorePolicy,
    records: [Option<StoreRecord<'a>>; N],
    next_sequence: u64,
}

impl<'a, const N: usize> Store<'a, N> {
    pub const fn new(policy: StorePolicy) -> Self {
        Self {
            policy,
            records: [None; N],
            next_sequence: 0,
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

    pub fn put(&mut self, envelope: HyfEnvelopeRef<'a>) -> Result<(), StoreError> {
        if self.policy.reject_expired_on_put && is_expired_at_creation(envelope) {
            return Err(StoreError::Expired);
        }
        if self.contains(envelope.message_id) {
            return Err(StoreError::Duplicate);
        }
        let Some(index) = self.first_free_index() else {
            return Err(StoreError::Full);
        };

        self.records[index] = Some(StoreRecord {
            envelope,
            sequence: self.next_sequence,
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(())
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
                && existing.envelope.expires_at_ms.0 <= now.0
            {
                *record = None;
                removed += 1;
            }
        }
        removed
    }

    pub fn pending(&self, out: &mut [StoredEnvelopeRef<'a>]) -> Result<usize, StoreError> {
        let count = self.len();
        if out.len() < count {
            return Err(StoreError::OutputTooSmall {
                actual: out.len(),
                required: count,
            });
        }

        let mut written = 0;
        for record in self.records.iter().flatten() {
            insert_pending(out, written, *record);
            written += 1;
        }
        Ok(written)
    }

    pub fn first_pending(&self) -> Option<StoredEnvelopeRef<'a>> {
        let mut selected: Option<StoreRecord<'a>> = None;
        for record in self.records.iter().flatten() {
            selected = match selected {
                Some(existing) if !record_precedes(*record, existing.envelope) => Some(existing),
                _ => Some(*record),
            };
        }
        selected.map(|record| StoredEnvelopeRef::new(record.envelope))
    }

    fn contains(&self, message_id: MessageId) -> bool {
        self.find_index(message_id).is_some()
    }

    fn find_index(&self, message_id: MessageId) -> Option<usize> {
        for (index, record) in self.records.iter().enumerate() {
            if let Some(existing) = record
                && existing.envelope.message_id == message_id
            {
                return Some(index);
            }
        }
        None
    }

    fn first_free_index(&self) -> Option<usize> {
        self.records.iter().position(Option::is_none)
    }
}

fn is_expired_at_creation(envelope: HyfEnvelopeRef<'_>) -> bool {
    envelope.expires_at_ms.0 <= envelope.created_at_ms.0
}

fn insert_pending<'a>(out: &mut [StoredEnvelopeRef<'a>], written: usize, record: StoreRecord<'a>) {
    let mut index = written;
    while index > 0 && record_precedes(record, out[index - 1].envelope) {
        out[index] = out[index - 1];
        index -= 1;
    }
    out[index] = StoredEnvelopeRef::new(record.envelope);
}

fn record_precedes(record: StoreRecord<'_>, envelope: HyfEnvelopeRef<'_>) -> bool {
    record.envelope.expires_at_ms.0 < envelope.expires_at_ms.0
        || (record.envelope.expires_at_ms.0 == envelope.expires_at_ms.0
            && record.envelope.created_at_ms.0 < envelope.created_at_ms.0)
        || (record.envelope.expires_at_ms.0 == envelope.expires_at_ms.0
            && record.envelope.created_at_ms.0 == envelope.created_at_ms.0
            && record.envelope.message_id.0 < envelope.message_id.0)
}

#[cfg(test)]
pub(crate) mod tests {
    use hyf_core::{MessageId, NodeId, TimestampMs};
    use hyf_wire::{HYF_WIRE_VERSION_0, HyfDestination, HyfEnvelopeRef, PayloadKind};

    use super::{Store, StoredEnvelopeRef};
    use crate::{StoreError, StorePolicy};

    #[test]
    fn store_puts_and_lists_pending_envelopes() -> Result<(), StoreError> {
        let mut store = Store::<2>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 300, b"one");
        let second = sample_envelope(MessageId([2; 32]), 100, 200, b"two");
        let mut pending = [StoredEnvelopeRef::new(first); 2];

        store.put(first)?;
        store.put(second)?;
        let count = store.pending(&mut pending)?;

        assert_eq!(count, 2);
        assert_eq!(pending[0].envelope.message_id, MessageId([2; 32]));
        assert_eq!(pending[1].envelope.message_id, MessageId([1; 32]));
        Ok(())
    }

    #[test]
    fn store_rejects_duplicate_expired_and_full_inputs() -> Result<(), StoreError> {
        let mut store = Store::<1>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 200, b"one");
        let duplicate = sample_envelope(MessageId([1; 32]), 100, 300, b"dupe");
        let expired = sample_envelope(MessageId([2; 32]), 100, 100, b"expired");
        let overflow = sample_envelope(MessageId([3; 32]), 100, 400, b"overflow");

        store.put(first)?;
        assert_eq!(store.put(duplicate), Err(StoreError::Duplicate));
        assert_eq!(store.put(expired), Err(StoreError::Expired));
        assert_eq!(store.put(overflow), Err(StoreError::Full));
        Ok(())
    }

    #[test]
    fn store_removes_existing_messages_and_reports_missing() -> Result<(), StoreError> {
        let mut store = Store::<2>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 200, b"one");

        store.put(first)?;
        assert_eq!(store.len(), 1);
        store.remove(MessageId([1; 32]))?;
        assert!(store.is_empty());
        assert_eq!(store.remove(MessageId([1; 32])), Err(StoreError::NotFound));
        Ok(())
    }

    #[test]
    fn store_expires_by_timestamp() -> Result<(), StoreError> {
        let mut store = Store::<3>::new(StorePolicy::new());
        store.put(sample_envelope(MessageId([1; 32]), 100, 200, b"one"))?;
        store.put(sample_envelope(MessageId([2; 32]), 100, 300, b"two"))?;
        store.put(sample_envelope(MessageId([3; 32]), 100, 400, b"three"))?;

        assert_eq!(store.expire_before(TimestampMs(300)), 2);
        assert_eq!(store.len(), 1);
        assert_eq!(store.expire_before(TimestampMs(300)), 0);
        Ok(())
    }

    #[test]
    fn pending_reports_short_output_before_writing_all_records() -> Result<(), StoreError> {
        let mut store = Store::<2>::new(StorePolicy::new());
        let first = sample_envelope(MessageId([1; 32]), 100, 200, b"one");
        let second = sample_envelope(MessageId([2; 32]), 100, 300, b"two");
        let mut pending = [StoredEnvelopeRef::new(first); 1];

        store.put(first)?;
        store.put(second)?;

        assert_eq!(
            store.pending(&mut pending),
            Err(StoreError::OutputTooSmall {
                actual: 1,
                required: 2,
            })
        );
        assert_eq!(pending[0].envelope.message_id, MessageId([1; 32]));
        Ok(())
    }

    #[test]
    fn pending_order_uses_expiry_created_at_and_message_id() -> Result<(), StoreError> {
        let mut store = Store::<3>::new(StorePolicy::new());
        let high_id = sample_envelope(MessageId([9; 32]), 100, 200, b"high");
        let low_id = sample_envelope(MessageId([1; 32]), 100, 200, b"low");
        let older = sample_envelope(MessageId([5; 32]), 90, 200, b"older");
        let mut pending = [StoredEnvelopeRef::new(high_id); 3];

        store.put(high_id)?;
        store.put(low_id)?;
        store.put(older)?;
        store.pending(&mut pending)?;

        assert_eq!(pending[0].envelope.message_id, MessageId([5; 32]));
        assert_eq!(pending[1].envelope.message_id, MessageId([1; 32]));
        assert_eq!(pending[2].envelope.message_id, MessageId([9; 32]));
        Ok(())
    }

    #[test]
    fn first_pending_returns_lowest_deterministic_record() -> Result<(), StoreError> {
        let mut store = Store::<3>::new(StorePolicy::new());
        let high_id = sample_envelope(MessageId([9; 32]), 100, 200, b"high");
        let low_id = sample_envelope(MessageId([1; 32]), 100, 200, b"low");

        store.put(high_id)?;
        store.put(low_id)?;

        assert_eq!(
            store
                .first_pending()
                .map(|stored| stored.envelope.message_id),
            Some(MessageId([1; 32]))
        );
        Ok(())
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
}
