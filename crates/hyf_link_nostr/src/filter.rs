use crate::{NostrError, NostrPublicKey};

pub const NOSTR_SUBSCRIPTION_ID_MAX_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NostrTagRef<'a> {
    values: &'a [&'a str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NostrTagsRef<'a> {
    tags: &'a [NostrTagRef<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NostrFilter<'a> {
    pub kinds: &'a [u16],
    pub authors: &'a [NostrPublicKey],
    pub p_tags: &'a [NostrPublicKey],
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NostrFilterTarget<'a> {
    pub kind: u16,
    pub author: NostrPublicKey,
    pub p_tags: &'a [NostrPublicKey],
    pub created_at: u64,
}

impl<'a> NostrTagRef<'a> {
    pub fn new(values: &'a [&'a str]) -> Result<Self, NostrError> {
        if values.is_empty() {
            return Err(NostrError::TagEmpty);
        }
        Ok(Self { values })
    }

    pub fn values(&self) -> &'a [&'a str] {
        self.values
    }

    pub fn name(&self) -> &'a str {
        self.values[0]
    }

    pub fn value(&self) -> Option<&'a str> {
        self.values.get(1).copied()
    }
}

impl<'a> NostrTagsRef<'a> {
    pub const fn new(tags: &'a [NostrTagRef<'a>]) -> Self {
        Self { tags }
    }

    pub const fn as_slice(&self) -> &'a [NostrTagRef<'a>] {
        self.tags
    }
}

impl<'a> NostrFilter<'a> {
    pub const fn empty() -> Self {
        Self {
            kinds: &[],
            authors: &[],
            p_tags: &[],
            since: None,
            until: None,
            limit: None,
        }
    }

    pub fn matches_target(&self, target: NostrFilterTarget<'_>) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&target.kind))
            && (self.authors.is_empty() || self.authors.contains(&target.author))
            && (self.p_tags.is_empty() || has_any_p_tag(target.p_tags, self.p_tags))
            && self.since.is_none_or(|since| target.created_at >= since)
            && self.until.is_none_or(|until| target.created_at <= until)
    }
}

pub fn validate_subscription_id(subscription_id: &str) -> Result<(), NostrError> {
    let len = subscription_id.len();
    if len == 0 {
        return Err(NostrError::InvalidSubscriptionId);
    }
    if len > NOSTR_SUBSCRIPTION_ID_MAX_LEN {
        return Err(NostrError::SubscriptionIdTooLong {
            len,
            maximum: NOSTR_SUBSCRIPTION_ID_MAX_LEN,
        });
    }
    Ok(())
}

pub fn matches_any_filter(filters: &[NostrFilter<'_>], target: NostrFilterTarget<'_>) -> bool {
    filters.iter().any(|filter| filter.matches_target(target))
}

fn has_any_p_tag(event_p_tags: &[NostrPublicKey], filter_p_tags: &[NostrPublicKey]) -> bool {
    filter_p_tags
        .iter()
        .any(|filter_tag| event_p_tags.contains(filter_tag))
}

#[cfg(test)]
mod tests {
    use super::{
        NostrFilter, NostrFilterTarget, NostrTagRef, NostrTagsRef, matches_any_filter,
        validate_subscription_id,
    };
    use crate::{NOSTR_SUBSCRIPTION_ID_MAX_LEN, NostrError, NostrPublicKey};

    const AUTHOR_A: NostrPublicKey = NostrPublicKey::from_bytes([0xa1; 32]);
    const AUTHOR_B: NostrPublicKey = NostrPublicKey::from_bytes([0xb2; 32]);
    const RECIPIENT_A: NostrPublicKey = NostrPublicKey::from_bytes([0xc3; 32]);
    const RECIPIENT_B: NostrPublicKey = NostrPublicKey::from_bytes([0xd4; 32]);

    #[test]
    fn tags_reject_empty_and_preserve_values() -> Result<(), NostrError> {
        assert!(matches!(NostrTagRef::new(&[]), Err(NostrError::TagEmpty)));
        let raw = ["p", "abc", "relay"];
        let tag = NostrTagRef::new(&raw)?;
        let tags = [tag];
        let tags = NostrTagsRef::new(&tags);
        assert_eq!(tag.name(), "p");
        assert_eq!(tag.value(), Some("abc"));
        assert_eq!(tags.as_slice()[0].values(), &raw);
        Ok(())
    }

    #[test]
    fn subscription_id_validation_enforces_nip01_boundary() {
        assert!(matches!(
            validate_subscription_id(""),
            Err(NostrError::InvalidSubscriptionId)
        ));
        assert!(validate_subscription_id(&"a".repeat(NOSTR_SUBSCRIPTION_ID_MAX_LEN)).is_ok());
        assert!(matches!(
            validate_subscription_id(&"a".repeat(NOSTR_SUBSCRIPTION_ID_MAX_LEN + 1)),
            Err(NostrError::SubscriptionIdTooLong {
                len: 65,
                maximum: 64
            })
        ));
    }

    #[test]
    fn filter_matches_and_conditions_within_filter() {
        let filter = NostrFilter {
            kinds: &[9775],
            authors: &[AUTHOR_A],
            p_tags: &[RECIPIENT_A],
            since: Some(10),
            until: Some(20),
            limit: Some(4),
        };
        assert_eq!(filter.limit, Some(4));
        assert!(filter.matches_target(target(9775, AUTHOR_A, &[RECIPIENT_A], 12)));
        assert!(!filter.matches_target(target(1, AUTHOR_A, &[RECIPIENT_A], 12)));
        assert!(!filter.matches_target(target(9775, AUTHOR_B, &[RECIPIENT_A], 12)));
        assert!(!filter.matches_target(target(9775, AUTHOR_A, &[RECIPIENT_B], 12)));
        assert!(!filter.matches_target(target(9775, AUTHOR_A, &[RECIPIENT_A], 9)));
        assert!(!filter.matches_target(target(9775, AUTHOR_A, &[RECIPIENT_A], 21)));
    }

    #[test]
    fn multiple_filters_are_or_conditions() {
        let filters = [
            NostrFilter {
                authors: &[AUTHOR_A],
                ..NostrFilter::empty()
            },
            NostrFilter {
                p_tags: &[RECIPIENT_B],
                ..NostrFilter::empty()
            },
        ];
        assert!(matches_any_filter(
            &filters,
            target(1, AUTHOR_A, &[RECIPIENT_A], 1)
        ));
        assert!(matches_any_filter(
            &filters,
            target(1, AUTHOR_B, &[RECIPIENT_B], 1)
        ));
        assert!(!matches_any_filter(
            &filters,
            target(1, AUTHOR_B, &[RECIPIENT_A], 1)
        ));
    }

    fn target<'a>(
        kind: u16,
        author: NostrPublicKey,
        p_tags: &'a [NostrPublicKey],
        created_at: u64,
    ) -> NostrFilterTarget<'a> {
        NostrFilterTarget {
            kind,
            author,
            p_tags,
            created_at,
        }
    }
}
