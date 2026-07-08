#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsCoreError {
    DestinationAppNameContainsDot,
    DestinationAspectContainsDot,
}

impl core::fmt::Display for RnsCoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DestinationAppNameContainsDot => {
                formatter.write_str("destination app name contains dot")
            }
            Self::DestinationAspectContainsDot => {
                formatter.write_str("destination aspect contains dot")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RnsCoreError;

    #[test]
    fn core_errors_have_stable_display_text() {
        assert_eq!(
            RnsCoreError::DestinationAppNameContainsDot.to_string(),
            "destination app name contains dot"
        );
        assert_eq!(
            RnsCoreError::DestinationAspectContainsDot.to_string(),
            "destination aspect contains dot"
        );
    }
}
