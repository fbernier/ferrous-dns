use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use std::borrow::Cow;
use std::hash::{Hash, Hasher};

/// ASCII-lowercases `domain` for cache lookups (RFC 1035 §2.3.3: DNS names
/// are case-insensitive), borrowing it when it already is.
#[inline]
pub(crate) fn normalize_domain(domain: &str) -> Cow<'_, str> {
    if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
        Cow::Borrowed(domain)
    } else {
        Cow::Owned(domain.to_ascii_lowercase())
    }
}

#[derive(Clone, Debug, Eq)]
pub struct CacheKey {
    pub domain: CompactString,
    pub record_type: RecordType,
}

impl CacheKey {
    /// Creates a new cache key, normalizing `domain` to ASCII-lowercase.
    /// Multi-byte UTF-8 sequences are kept byte-for-byte.
    #[inline]
    pub fn new(domain: &str, record_type: RecordType) -> Self {
        let domain = if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
            CompactString::from(domain)
        } else {
            let mut lowered = CompactString::from(domain);
            lowered.make_ascii_lowercase();
            lowered
        };
        Self {
            domain,
            record_type,
        }
    }

    /// For a name that already went through [`normalize_domain`]: skips the
    /// case scan [`Self::new`] would repeat.
    #[inline]
    pub(crate) fn from_lowercase(domain: &str, record_type: RecordType) -> Self {
        debug_assert!(
            domain.bytes().all(|b| !b.is_ascii_uppercase()),
            "CacheKey::from_lowercase expects an ASCII-lowercased domain; got `{domain}`"
        );
        Self {
            domain: CompactString::from(domain),
            record_type,
        }
    }
}

impl Hash for CacheKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.as_str().hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}

impl PartialEq for CacheKey {
    #[inline]
    fn eq(&self, other: &CacheKey) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

/// A zero-copy view that hashes exactly like the [`CacheKey`] for the same
/// name, so the bloom filter can be probed without building a key.
#[derive(Debug)]
pub struct BorrowedKey<'a> {
    pub domain: &'a str,
    pub record_type: RecordType,
}

impl<'a> BorrowedKey<'a> {
    /// `domain` must already be ASCII-lowercased, as a `CacheKey` stores it,
    /// or the two hash differently.
    #[inline]
    pub fn new(domain: &'a str, record_type: RecordType) -> Self {
        debug_assert!(
            domain.bytes().all(|b| !b.is_ascii_uppercase()),
            "BorrowedKey domain must be ASCII-lowercased by the caller; got `{}`",
            domain
        );
        Self {
            domain,
            record_type,
        }
    }
}

impl<'a> Hash for BorrowedKey<'a> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}
