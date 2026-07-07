#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NodeRole {
    PersonalNode,
    AnchorNode,
    GatewayNode,
}

#[cfg(test)]
mod tests {
    use super::NodeRole;

    #[test]
    fn roles_are_distinct() {
        assert_ne!(NodeRole::PersonalNode, NodeRole::AnchorNode);
        assert_ne!(NodeRole::AnchorNode, NodeRole::GatewayNode);
    }
}
