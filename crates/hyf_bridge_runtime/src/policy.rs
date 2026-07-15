use hyf_bridge_core::BridgeProtocol;

use crate::{BridgeOrigin, BridgeRuntimeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeRoutePolicy<const MAX_EGRESS: usize> {
    pub allow_echo: bool,
    pub egress_protocols: [Option<BridgeProtocol>; MAX_EGRESS],
}

impl<const MAX_EGRESS: usize> BridgeRoutePolicy<MAX_EGRESS> {
    pub const fn new(
        allow_echo: bool,
        egress_protocols: [Option<BridgeProtocol>; MAX_EGRESS],
    ) -> Self {
        Self {
            allow_echo,
            egress_protocols,
        }
    }

    pub const fn no_echo(egress_protocols: [Option<BridgeProtocol>; MAX_EGRESS]) -> Self {
        Self::new(false, egress_protocols)
    }

    pub fn selected_egress_count(&self, origin: BridgeOrigin) -> usize {
        let mut selected = [false; 4];
        let mut count = 0;
        for protocol in self.egress_protocols.iter().flatten().copied() {
            if self.protocol_is_blocked(origin, protocol) || mark_seen(&mut selected, protocol) {
                continue;
            }
            count += 1;
        }
        count
    }

    pub fn select_egress(
        &self,
        origin: BridgeOrigin,
        output: &mut [BridgeProtocol],
    ) -> Result<usize, BridgeRuntimeError> {
        let required = self.selected_egress_count(origin);
        if output.len() < required {
            return Err(BridgeRuntimeError::OutputTooSmall {
                actual: output.len(),
                required,
            });
        }

        let mut selected = [false; 4];
        let mut count = 0;
        for protocol in self.egress_protocols.iter().flatten().copied() {
            if self.protocol_is_blocked(origin, protocol) || mark_seen(&mut selected, protocol) {
                continue;
            }
            output[count] = protocol;
            count += 1;
        }
        Ok(count)
    }

    pub fn protocol_is_blocked(&self, origin: BridgeOrigin, protocol: BridgeProtocol) -> bool {
        !self.allow_echo && origin.protocol == protocol
    }
}

impl<const MAX_EGRESS: usize> Default for BridgeRoutePolicy<MAX_EGRESS> {
    fn default() -> Self {
        Self {
            allow_echo: false,
            egress_protocols: [None; MAX_EGRESS],
        }
    }
}

fn mark_seen(seen: &mut [bool; 4], protocol: BridgeProtocol) -> bool {
    let index = protocol_index(protocol);
    let was_seen = seen[index];
    seen[index] = true;
    was_seen
}

const fn protocol_index(protocol: BridgeProtocol) -> usize {
    match protocol {
        BridgeProtocol::Hyf => 0,
        BridgeProtocol::BitChat => 1,
        BridgeProtocol::Lxmf => 2,
        BridgeProtocol::Nostr => 3,
    }
}

#[cfg(test)]
mod tests {
    use hyf_bridge_core::BridgeProtocol;

    use super::BridgeRoutePolicy;
    use crate::{BridgeOrigin, BridgeRuntimeError};

    #[test]
    fn route_policy_blocks_origin_protocol_by_default() -> Result<(), BridgeRuntimeError> {
        let policy = BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::BitChat),
            Some(BridgeProtocol::Lxmf),
            Some(BridgeProtocol::BitChat),
            Some(BridgeProtocol::Nostr),
        ]);
        let origin = BridgeOrigin::new(BridgeProtocol::BitChat, [1; 32]);
        let mut output = [BridgeProtocol::Hyf; 3];

        let count = policy.select_egress(origin, &mut output)?;

        assert_eq!(count, 2);
        assert_eq!(
            &output[..count],
            &[BridgeProtocol::Lxmf, BridgeProtocol::Nostr]
        );
        assert_eq!(policy.selected_egress_count(origin), 2);
        Ok(())
    }

    #[test]
    fn route_policy_can_allow_echo_explicitly() -> Result<(), BridgeRuntimeError> {
        let policy = BridgeRoutePolicy::new(
            true,
            [
                Some(BridgeProtocol::BitChat),
                Some(BridgeProtocol::Lxmf),
                None,
            ],
        );
        let origin = BridgeOrigin::new(BridgeProtocol::BitChat, [1; 32]);
        let mut output = [BridgeProtocol::Hyf; 3];

        let count = policy.select_egress(origin, &mut output)?;

        assert_eq!(count, 2);
        assert_eq!(
            &output[..count],
            &[BridgeProtocol::BitChat, BridgeProtocol::Lxmf]
        );
        Ok(())
    }

    #[test]
    fn route_policy_reports_required_output_capacity() {
        let policy = BridgeRoutePolicy::no_echo([
            Some(BridgeProtocol::BitChat),
            Some(BridgeProtocol::Lxmf),
            Some(BridgeProtocol::Nostr),
        ]);
        let origin = BridgeOrigin::new(BridgeProtocol::Hyf, [1; 32]);
        let mut output = [BridgeProtocol::Hyf; 2];

        assert_eq!(
            policy.select_egress(origin, &mut output),
            Err(BridgeRuntimeError::OutputTooSmall {
                actual: 2,
                required: 3,
            })
        );
    }
}
