use core::{fmt, str};

use crate::{NostrError, NostrTagRef, NostrTagsRef};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StoredString<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StoredNostrTag<const VALUES_MAX: usize, const VALUE_MAX: usize> {
    values: [StoredString<VALUE_MAX>; VALUES_MAX],
    len: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StoredNostrTags<
    const TAGS_MAX: usize,
    const VALUES_MAX: usize,
    const VALUE_MAX: usize,
> {
    tags: [StoredNostrTag<VALUES_MAX, VALUE_MAX>; TAGS_MAX],
    len: usize,
}

impl<const N: usize> StoredString<N> {
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, NostrError> {
        let bytes = value.as_bytes();
        if bytes.len() > N {
            return Err(NostrError::StoredStringTooLarge {
                actual: bytes.len(),
                maximum: N,
            });
        }

        let mut stored = Self::empty();
        stored.bytes[..bytes.len()].copy_from_slice(bytes);
        stored.len = bytes.len();
        Ok(stored)
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn as_str(&self) -> Result<&str, NostrError> {
        str::from_utf8(&self.bytes[..self.len]).map_err(|_| NostrError::Utf8)
    }
}

impl<const N: usize> Default for StoredString<N> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const N: usize> fmt::Debug for StoredString<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredString")
            .field("capacity", &N)
            .field("len", &self.len)
            .finish()
    }
}

impl<const VALUES_MAX: usize, const VALUE_MAX: usize> StoredNostrTag<VALUES_MAX, VALUE_MAX> {
    pub(crate) const fn empty() -> Self {
        Self {
            values: [StoredString::empty(); VALUES_MAX],
            len: 0,
        }
    }

    pub(crate) fn from_ref(tag: NostrTagRef<'_>) -> Result<Self, NostrError> {
        let values = tag.values();
        if values.len() > VALUES_MAX {
            return Err(NostrError::TagValueCountTooLarge {
                actual: values.len(),
                maximum: VALUES_MAX,
            });
        }

        let mut stored = Self::empty();
        for (index, value) in values.iter().enumerate() {
            if value.len() > VALUE_MAX {
                return Err(NostrError::TagValueTooLarge {
                    actual: value.len(),
                    maximum: VALUE_MAX,
                });
            }
            stored.values[index] = StoredString::from_str(value)?;
        }
        stored.len = values.len();
        Ok(stored)
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn value(&self, index: usize) -> Result<Option<&str>, NostrError> {
        if index >= self.len {
            return Ok(None);
        }
        self.values[index].as_str().map(Some)
    }
}

impl<const VALUES_MAX: usize, const VALUE_MAX: usize> Default
    for StoredNostrTag<VALUES_MAX, VALUE_MAX>
{
    fn default() -> Self {
        Self::empty()
    }
}

impl<const VALUES_MAX: usize, const VALUE_MAX: usize> fmt::Debug
    for StoredNostrTag<VALUES_MAX, VALUE_MAX>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredNostrTag")
            .field("value_capacity", &VALUES_MAX)
            .field("value_char_capacity", &VALUE_MAX)
            .field("len", &self.len)
            .finish()
    }
}

impl<const TAGS_MAX: usize, const VALUES_MAX: usize, const VALUE_MAX: usize>
    StoredNostrTags<TAGS_MAX, VALUES_MAX, VALUE_MAX>
{
    pub(crate) const fn empty() -> Self {
        Self {
            tags: [StoredNostrTag::empty(); TAGS_MAX],
            len: 0,
        }
    }

    pub(crate) fn from_ref(tags: NostrTagsRef<'_>) -> Result<Self, NostrError> {
        let tag_refs = tags.as_slice();
        if tag_refs.len() > TAGS_MAX {
            return Err(NostrError::TagCountTooLarge {
                actual: tag_refs.len(),
                maximum: TAGS_MAX,
            });
        }

        let mut stored = Self::empty();
        for (index, tag) in tag_refs.iter().enumerate() {
            stored.tags[index] = StoredNostrTag::from_ref(*tag)?;
        }
        stored.len = tag_refs.len();
        Ok(stored)
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn tag(&self, index: usize) -> Option<&StoredNostrTag<VALUES_MAX, VALUE_MAX>> {
        if index >= self.len {
            return None;
        }
        Some(&self.tags[index])
    }
}

impl<const TAGS_MAX: usize, const VALUES_MAX: usize, const VALUE_MAX: usize> Default
    for StoredNostrTags<TAGS_MAX, VALUES_MAX, VALUE_MAX>
{
    fn default() -> Self {
        Self::empty()
    }
}

impl<const TAGS_MAX: usize, const VALUES_MAX: usize, const VALUE_MAX: usize> fmt::Debug
    for StoredNostrTags<TAGS_MAX, VALUES_MAX, VALUE_MAX>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredNostrTags")
            .field("tag_capacity", &TAGS_MAX)
            .field("value_capacity", &VALUES_MAX)
            .field("value_char_capacity", &VALUE_MAX)
            .field("len", &self.len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{StoredNostrTag, StoredNostrTags, StoredString};
    use crate::{
        HYF_NOSTR_MAX_TAG_VALUE_CHARS, HYF_NOSTR_MAX_TAG_VALUES, HYF_NOSTR_MAX_TAGS, NostrError,
        NostrTagRef, NostrTagsRef,
    };

    #[test]
    fn stored_string_preserves_utf8_without_debug_content() -> Result<(), NostrError> {
        let stored = StoredString::<16>::from_str("hyf")?;

        assert_eq!(stored.len(), 3);
        assert!(!stored.is_empty());
        assert_eq!(stored.as_str()?, "hyf");
        assert!(!format!("{stored:?}").contains("hyf"));
        Ok(())
    }

    #[test]
    fn stored_string_rejects_over_limit_values() {
        assert_eq!(
            StoredString::<2>::from_str("hyf"),
            Err(NostrError::StoredStringTooLarge {
                actual: 3,
                maximum: 2,
            })
        );
    }

    #[test]
    fn stored_tag_preserves_values_without_debug_content() -> Result<(), NostrError> {
        let values = ["p", "abc"];
        let tag =
            StoredNostrTag::<HYF_NOSTR_MAX_TAG_VALUES, HYF_NOSTR_MAX_TAG_VALUE_CHARS>::from_ref(
                NostrTagRef::new(&values)?,
            )?;

        assert_eq!(tag.len(), 2);
        assert!(!tag.is_empty());
        assert_eq!(tag.value(0)?, Some("p"));
        assert_eq!(tag.value(1)?, Some("abc"));
        assert_eq!(tag.value(2)?, None);
        assert!(!format!("{tag:?}").contains("abc"));
        Ok(())
    }

    #[test]
    fn stored_tag_rejects_too_many_values() -> Result<(), NostrError> {
        let values = ["p", "a", "b"];
        assert_eq!(
            StoredNostrTag::<2, HYF_NOSTR_MAX_TAG_VALUE_CHARS>::from_ref(NostrTagRef::new(
                &values
            )?),
            Err(NostrError::TagValueCountTooLarge {
                actual: 3,
                maximum: 2,
            })
        );
        Ok(())
    }

    #[test]
    fn stored_tag_rejects_too_long_values() -> Result<(), NostrError> {
        let value = "a".repeat(HYF_NOSTR_MAX_TAG_VALUE_CHARS + 1);
        let values = ["p", value.as_str()];
        assert_eq!(
            StoredNostrTag::<HYF_NOSTR_MAX_TAG_VALUES, HYF_NOSTR_MAX_TAG_VALUE_CHARS>::from_ref(
                NostrTagRef::new(&values)?
            ),
            Err(NostrError::TagValueTooLarge {
                actual: HYF_NOSTR_MAX_TAG_VALUE_CHARS + 1,
                maximum: HYF_NOSTR_MAX_TAG_VALUE_CHARS,
            })
        );
        Ok(())
    }

    #[test]
    fn stored_tags_preserve_order_and_reject_overflow() -> Result<(), NostrError> {
        let p_values = ["p", "abc"];
        let t_values = ["t", "hyf"];
        let tags = [NostrTagRef::new(&p_values)?, NostrTagRef::new(&t_values)?];
        let stored = StoredNostrTags::<
            HYF_NOSTR_MAX_TAGS,
            HYF_NOSTR_MAX_TAG_VALUES,
            HYF_NOSTR_MAX_TAG_VALUE_CHARS,
        >::from_ref(NostrTagsRef::new(&tags))?;

        assert_eq!(stored.len(), 2);
        assert!(!stored.is_empty());
        assert_eq!(
            stored.tag(0).and_then(|tag| tag.value(0).ok()).flatten(),
            Some("p")
        );
        assert_eq!(
            stored.tag(1).and_then(|tag| tag.value(1).ok()).flatten(),
            Some("hyf")
        );
        assert_eq!(stored.tag(2), None);
        assert!(!format!("{stored:?}").contains("hyf"));

        let overflow = [NostrTagRef::new(&p_values)?, NostrTagRef::new(&p_values)?];
        assert_eq!(
            StoredNostrTags::<1, HYF_NOSTR_MAX_TAG_VALUES, HYF_NOSTR_MAX_TAG_VALUE_CHARS>::from_ref(
                NostrTagsRef::new(&overflow)
            ),
            Err(NostrError::TagCountTooLarge {
                actual: 2,
                maximum: 1,
            })
        );
        Ok(())
    }
}
