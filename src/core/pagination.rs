#![forbid(unsafe_code)]
//! Pagination primitives for Paymob list endpoints (`US-1.3.0/unit-4`).
//!
//! Provides [`PaginatedResponse<T>`] for deserializing standard Paymob /
//! Django REST Framework style paginated payloads (`count`, `next`, `previous`,
//! `results`) and [`PageQuery`] for building `?page=N` query parameters.

use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

/// Standard paginated envelope returned by Paymob list endpoints.
///
/// # Examples
///
/// ```
/// use some_paymob::core::pagination::PaginatedResponse;
///
/// let json = r#"{
///     "count": 2,
///     "next": "https://accept.paymob.com/api/ecommerce/orders?page=2",
///     "previous": null,
///     "results": ["ord_1", "ord_2"]
/// }"#;
///
/// let page: PaginatedResponse<String> = serde_json::from_str(json).unwrap();
/// assert_eq!(page.count, 2);
/// assert!(page.has_next());
/// assert!(!page.has_previous());
/// assert_eq!(page.next_page_number(), Some(2));
/// assert_eq!(page.results, vec!["ord_1", "ord_2"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Total number of matching records across all pages.
    pub count: u64,
    /// Optional URL pointing to the next page of results.
    pub next: Option<String>,
    /// Optional URL pointing to the previous page of results.
    pub previous: Option<String>,
    /// Items returned in the current page.
    pub results: Vec<T>,
}

impl<T> Default for PaginatedResponse<T> {
    fn default() -> Self {
        Self {
            count: 0,
            next: None,
            previous: None,
            results: Vec::new(),
        }
    }
}

impl<T> PaginatedResponse<T> {
    /// Returns `true` if a subsequent page URL is present.
    #[must_use]
    pub fn has_next(&self) -> bool {
        self.next.is_some()
    }

    /// Returns `true` if a preceding page URL is present.
    #[must_use]
    pub fn has_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// Returns `true` if the current page contains zero items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Returns the number of items in the current page.
    #[must_use]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Extracts the `page` query parameter from `next`, if present and valid (`>= 1`).
    #[must_use]
    pub fn next_page_number(&self) -> Option<u32> {
        extract_page_number(self.next.as_deref())
    }

    /// Extracts the `page` query parameter from `previous`, if present and valid (`>= 1`).
    #[must_use]
    pub fn previous_page_number(&self) -> Option<u32> {
        extract_page_number(self.previous.as_deref())
    }

    /// Transforms each item in `results` while preserving pagination metadata.
    pub fn map<U, F>(self, f: F) -> PaginatedResponse<U>
    where
        F: FnMut(T) -> U,
    {
        PaginatedResponse {
            count: self.count,
            next: self.next,
            previous: self.previous,
            results: self.results.into_iter().map(f).collect(),
        }
    }
}

fn parse_pagination_url(raw: &str) -> Option<Url> {
    if let Ok(url) = Url::parse(raw) {
        return Some(url);
    }
    if raw.starts_with('/') || raw.starts_with('?') {
        return Url::parse("https://paymob.invalid").ok()?.join(raw).ok();
    }
    None
}

fn extract_page_number(raw_url: Option<&str>) -> Option<u32> {
    let parsed = parse_pagination_url(raw_url?)?;
    parsed
        .query_pairs()
        .find(|(key, _)| key == "page")
        .and_then(|(_, value)| value.parse::<u32>().ok())
        .filter(|&page| page >= 1)
}

fn default_page() -> u32 {
    1
}

#[derive(Deserialize)]
struct RawPageQuery {
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default)]
    page_size: Option<u32>,
}

impl From<RawPageQuery> for PageQuery {
    fn from(raw: RawPageQuery) -> Self {
        Self {
            page: raw.page.max(1),
            page_size: raw.page_size.map(|size| size.max(1)),
        }
    }
}

/// Builder and query serializer for Paymob `?page=N` pagination parameters.
///
/// Page numbers and optional page sizes are normalized to be at least `1`
/// both in constructors and during deserialization.
///
/// # Examples
///
/// ```
/// use some_paymob::core::pagination::PageQuery;
///
/// let query = PageQuery::new(2).with_page_size(25);
/// assert_eq!(query.page(), 2);
/// assert_eq!(query.page_size(), Some(25));
/// assert_eq!(query.to_query_string(), "?page=2&page_size=25");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawPageQuery")]
pub struct PageQuery {
    /// 1-indexed page number.
    #[serde(default = "default_page")]
    page: u32,
    /// Optional number of items requested per page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    page_size: Option<u32>,
}

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: None,
        }
    }
}

impl PageQuery {
    /// Creates a new [`PageQuery`] for the given 1-indexed `page` number.
    ///
    /// Passing `0` is clamped to `1`.
    #[must_use]
    pub fn new(page: u32) -> Self {
        Self {
            page: page.max(1),
            page_size: None,
        }
    }

    /// Sets the 1-indexed `page` number, clamping `0` to `1`.
    #[must_use]
    pub fn with_page(mut self, page: u32) -> Self {
        self.page = page.max(1);
        self
    }

    /// Sets the optional `page_size`, clamping `0` to `1`.
    #[must_use]
    pub fn with_page_size(mut self, page_size: u32) -> Self {
        self.page_size = Some(page_size.max(1));
        self
    }

    /// Returns the 1-indexed page number.
    #[must_use]
    pub const fn page(&self) -> u32 {
        self.page
    }

    /// Returns the optional page size.
    #[must_use]
    pub const fn page_size(&self) -> Option<u32> {
        self.page_size
    }

    /// Returns a [`PageQuery`] targeting the next page (`page + 1`, saturating).
    #[must_use]
    pub const fn next_page(&self) -> Self {
        Self {
            page: self.page.saturating_add(1),
            page_size: self.page_size,
        }
    }

    /// Serializes the pagination parameters into a `?page=N` query string.
    #[must_use]
    pub fn to_query_string(&self) -> String {
        match self.page_size {
            Some(size) => format!("?page={}&page_size={size}", self.page),
            None => format!("?page={}", self.page),
        }
    }

    /// Returns the pagination parameters as key-value pairs for HTTP clients.
    #[must_use]
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::with_capacity(2);
        pairs.push(("page", self.page.to_string()));
        if let Some(size) = self.page_size {
            pairs.push(("page_size", size.to_string()));
        }
        pairs
    }
}

impl fmt::Display for PageQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_query_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_1_3_4_paginated_response_deserialization_and_helpers() {
        let raw = r#"{
            "count": 42,
            "next": "https://accept.paymob.com/api/ecommerce/orders?page=3&page_size=20",
            "previous": "https://accept.paymob.com/api/ecommerce/orders?page=1&page_size=20",
            "results": [101, 102, 103]
        }"#;

        let resp: PaginatedResponse<u64> = serde_json::from_str(raw).expect("valid JSON");
        assert_eq!(
            (
                resp.count,
                resp.has_next(),
                resp.has_previous(),
                resp.is_empty(),
                resp.len(),
                resp.next_page_number(),
                resp.previous_page_number(),
            ),
            (42, true, true, false, 3, Some(3), Some(1))
        );

        let mapped = resp.map(|id| format!("ord_{id}"));
        assert_eq!(
            (mapped.count, mapped.results),
            (42, vec!["ord_101".to_owned(), "ord_102".to_owned(), "ord_103".to_owned()])
        );
    }

    #[test]
    fn tc_1_3_4_paginated_response_empty_and_last_page() {
        let empty: PaginatedResponse<String> = PaginatedResponse::default();
        assert_eq!(
            (
                empty.count,
                empty.has_next(),
                empty.has_previous(),
                empty.is_empty(),
                empty.len(),
                empty.next_page_number(),
                empty.previous_page_number(),
            ),
            (0, false, false, true, 0, None, None)
        );

        let last_page = PaginatedResponse {
            count: 25,
            next: None,
            previous: Some("/api/ecommerce/orders?page=2&page_size=20".to_string()),
            results: vec![21_u8, 22, 23, 24, 25],
        };
        assert_eq!(
            (last_page.has_next(), last_page.next_page_number(), last_page.previous_page_number()),
            (false, None, Some(2))
        );
    }

    #[test]
    fn tc_1_3_4_paginated_response_relative_and_invalid_urls() {
        let relative = PaginatedResponse {
            count: 10,
            next: Some("?page=4&page_size=10".to_string()),
            previous: Some("/api/orders?page=2".to_string()),
            results: vec![1_u8],
        };
        assert_eq!(
            (relative.next_page_number(), relative.previous_page_number()),
            (Some(4), Some(2))
        );

        let invalid = PaginatedResponse {
            count: 1,
            next: Some("https://accept.paymob.com/api/orders?page=0".to_string()),
            previous: Some("https://accept.paymob.com/api/orders?page=4294967296".to_string()),
            results: vec![1_u8],
        };
        assert_eq!(
            (invalid.next_page_number(), invalid.previous_page_number()),
            (None, None)
        );
    }

    #[test]
    fn tc_1_3_4_paginated_response_malformed_urls_and_json() {
        let resp = PaginatedResponse {
            count: 1,
            next: Some("not a valid url".to_string()),
            previous: Some("https://accept.paymob.com/api/orders?page=abc".to_string()),
            results: vec![1_u8],
        };
        assert_eq!(
            (resp.next_page_number(), resp.previous_page_number()),
            (None, None)
        );

        let bad_json = serde_json::from_str::<PaginatedResponse<u8>>(r#"{"count":"bad"}"#);
        assert!(bad_json.is_err());
    }

    #[test]
    fn tc_1_3_4_page_query_builder_and_serialization() {
        let default_q = PageQuery::default();
        assert_eq!(
            (
                default_q.page(),
                default_q.page_size(),
                default_q.to_query_string(),
                default_q.to_query_pairs(),
            ),
            (1, None, "?page=1".to_string(), vec![("page", "1".to_string())])
        );

        let custom_q = PageQuery::new(2).with_page(4).with_page_size(50);
        assert_eq!(
            (
                custom_q.page(),
                custom_q.page_size(),
                custom_q.to_query_string(),
                custom_q.next_page().page(),
            ),
            (4, Some(50), "?page=4&page_size=50".to_string(), 5)
        );
    }

    #[test]
    fn tc_1_3_4_page_query_boundary_clamping_and_serde_normalization() {
        let zero_q = PageQuery::new(0).with_page_size(0);
        let clamped_q = PageQuery::default().with_page(0);
        let max_q = PageQuery::new(u32::MAX).next_page();
        assert_eq!(
            (zero_q.page(), zero_q.page_size(), clamped_q.page(), max_q.page()),
            (1, Some(1), 1, u32::MAX)
        );

        let deserialized_zero: PageQuery =
            serde_json::from_str(r#"{"page":0,"page_size":0}"#).expect("deserialize");
        assert_eq!(
            (deserialized_zero.page(), deserialized_zero.page_size()),
            (1, Some(1))
        );
    }
}
