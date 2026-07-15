use hyf_bridge_core::BridgeMessageKey;

use crate::BridgeRuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeDedupeSet<const N: usize> {
    keys: [Option<BridgeMessageKey>; N],
    next_index: usize,
    len: usize,
}

impl<const N: usize> BridgeDedupeSet<N> {
    pub const fn new() -> Self {
        Self {
            keys: [None; N],
            next_index: 0,
            len: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, key: BridgeMessageKey) -> bool {
        self.keys.iter().flatten().any(|stored| *stored == key)
    }

    pub fn insert(&mut self, key: BridgeMessageKey) -> Result<bool, BridgeRuntimeError> {
        if self.contains(key) {
            return Ok(false);
        }
        if N == 0 {
            return Err(BridgeRuntimeError::DedupeCapacityZero);
        }

        self.keys[self.next_index] = Some(key);
        self.next_index = (self.next_index + 1) % N;
        if self.len < N {
            self.len += 1;
        }
        Ok(true)
    }
}

impl<const N: usize> Default for BridgeDedupeSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::BridgeMessageKey;
    use hyf_core::{CommunityId, MessageId};

    use super::BridgeDedupeSet;
    use crate::BridgeRuntimeError;

    #[test]
    fn dedupe_keys_by_room_and_message_id() -> Result<(), BridgeRuntimeError> {
        let mut dedupe = BridgeDedupeSet::<2>::new();
        let first = key([1; 16], [2; 32]);
        let same_message_different_room = key([3; 16], [2; 32]);

        assert!(dedupe.insert(first)?);
        assert!(!dedupe.insert(first)?);
        assert!(dedupe.insert(same_message_different_room)?);
        assert!(dedupe.contains(first));
        assert!(dedupe.contains(same_message_different_room));
        assert_eq!(dedupe.len(), 2);
        Ok(())
    }

    #[test]
    fn dedupe_eviction_is_bounded_and_deterministic() -> Result<(), BridgeRuntimeError> {
        let mut dedupe = BridgeDedupeSet::<2>::new();
        let first = key([1; 16], [1; 32]);
        let second = key([2; 16], [2; 32]);
        let third = key([3; 16], [3; 32]);

        assert!(dedupe.insert(first)?);
        assert!(dedupe.insert(second)?);
        assert!(dedupe.insert(third)?);

        assert!(!dedupe.contains(first));
        assert!(dedupe.contains(second));
        assert!(dedupe.contains(third));
        assert_eq!(dedupe.len(), 2);
        Ok(())
    }

    #[test]
    fn zero_capacity_dedupe_fails_closed() {
        let mut dedupe = BridgeDedupeSet::<0>::new();

        assert_eq!(
            dedupe.insert(key([1; 16], [1; 32])),
            Err(BridgeRuntimeError::DedupeCapacityZero)
        );
    }

    fn key(room_id: [u8; 16], message_id: [u8; 32]) -> BridgeMessageKey {
        BridgeMessageKey {
            room_id: CommunityId(room_id),
            message_id: MessageId(message_id),
        }
    }
}
