#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MessageId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommunityId(pub [u8; 16]);

#[cfg(test)]
mod tests {
    use super::{CommunityId, MessageId, NodeId};

    #[test]
    fn node_ids_are_copyable_and_comparable() {
        let first = NodeId([1; 32]);
        let second = first;

        assert_eq!(first, second);
    }

    #[test]
    fn message_ids_preserve_bytes() {
        let bytes = [2; 32];
        let id = MessageId(bytes);

        assert_eq!(id.0, bytes);
    }

    #[test]
    fn community_ids_use_sixteen_bytes() {
        let bytes = [3; 16];
        let id = CommunityId(bytes);

        assert_eq!(id.0, bytes);
    }
}
