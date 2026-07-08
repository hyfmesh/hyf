use crate::{RNodeEvent, RNodeHardwareError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RNodeState {
    flow_control: bool,
    interface_ready: bool,
    last_error: Option<RNodeHardwareError>,
}

impl RNodeState {
    pub const fn new(flow_control: bool) -> Self {
        Self {
            flow_control,
            interface_ready: !flow_control,
            last_error: None,
        }
    }

    pub const fn flow_control(&self) -> bool {
        self.flow_control
    }

    pub const fn interface_ready(&self) -> bool {
        self.interface_ready
    }

    pub const fn last_error(&self) -> Option<RNodeHardwareError> {
        self.last_error
    }

    pub const fn can_transmit(&self) -> bool {
        !self.flow_control || self.interface_ready
    }

    pub fn mark_tx_started(&mut self) {
        if self.flow_control {
            self.interface_ready = false;
        }
    }

    pub fn apply_event(&mut self, event: &RNodeEvent<'_>) {
        match event {
            RNodeEvent::Ready => {
                self.interface_ready = true;
            }
            RNodeEvent::Error(error) => {
                self.last_error = Some(*error);
                self.interface_ready = false;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RNodeState;
    use crate::{RNodeEvent, RNodeHardwareError};

    #[test]
    fn state_without_flow_control_is_ready_by_default() {
        let state = RNodeState::new(false);

        assert!(!state.flow_control());
        assert!(state.interface_ready());
        assert!(state.can_transmit());
    }

    #[test]
    fn flow_control_state_toggles_on_tx_and_ready() {
        let mut state = RNodeState::new(true);

        assert!(!state.can_transmit());
        state.apply_event(&RNodeEvent::Ready);
        assert!(state.can_transmit());
        state.mark_tx_started();
        assert!(!state.can_transmit());
    }

    #[test]
    fn hardware_errors_block_ready_state() {
        let mut state = RNodeState::new(true);
        state.apply_event(&RNodeEvent::Ready);
        state.apply_event(&RNodeEvent::Error(RNodeHardwareError::QueueFull));

        assert!(!state.interface_ready());
        assert_eq!(state.last_error(), Some(RNodeHardwareError::QueueFull));
    }
}
