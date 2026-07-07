use crate::RnsCoreError;

pub fn validate_destination_name(app_name: &str, aspects: &[&str]) -> Result<(), RnsCoreError> {
    if app_name.contains('.') {
        return Err(RnsCoreError::DestinationAppNameContainsDot);
    }

    for aspect in aspects {
        if aspect.contains('.') {
            return Err(RnsCoreError::DestinationAspectContainsDot);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_destination_name;
    use crate::RnsCoreError;

    #[test]
    fn destination_name_allows_reticulum_empty_components() {
        assert_eq!(validate_destination_name("", &[]), Ok(()));
        assert_eq!(validate_destination_name("app", &[""]), Ok(()));
    }

    #[test]
    fn destination_name_allows_regular_components() {
        assert_eq!(validate_destination_name("app", &["aspect"]), Ok(()));
        assert_eq!(
            validate_destination_name("app", &["aspect", "subaspect"]),
            Ok(())
        );
    }

    #[test]
    fn destination_name_rejects_dotted_app_name() {
        assert_eq!(
            validate_destination_name("app.bad", &[]),
            Err(RnsCoreError::DestinationAppNameContainsDot)
        );
    }

    #[test]
    fn destination_name_rejects_dotted_aspect() {
        assert_eq!(
            validate_destination_name("app", &["bad.aspect"]),
            Err(RnsCoreError::DestinationAspectContainsDot)
        );
    }
}
