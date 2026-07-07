#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsCoreError {
    DestinationAppNameContainsDot,
    DestinationAspectContainsDot,
}
