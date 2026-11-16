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

    /// Extracts the `page` query parameter from `next`, if present and valid.
    #[must_use]
    pub fn next_page_number(&self) -> Option<u32> {
        extract_page_number(self.next.as_deref())
    }

    /// Extracts the `page` query parameter from `previous`, if present and valid.
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

fn extract_page_number(raw_url: Option<&str>) -> Option<u32> {
    let parsed = Url::parse(raw_url?).ok()?;
    parsed
        .query_pairs()
        .find(|(key, _)| key == "page")
        .and_then(|(_, value)| value.parse::<u32>().ok())
}

fn default_page() -> u32 {
    1
}

/// Builder and query serializer for Paymob `?page=N` pagination parameters.
///
/// Page numbers and optional page sizes are normalized to be at least `1`.
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
        assert_eq!(resp.count, 42);
        assert!(resp.has_next());
        assert!(resp.has_previous());
        assert!(!resp.is_empty());
        assert_eq!(resp.len(), 3);
        assert_eq!(resp.next_page_number(), Some(3));
        assert_eq!(resp.previous_page_number(), Some(1));

        let mapped = resp.map(|id| format!("ord_{id}"));
        assert_eq!(mapped.count, 42);
        assert_eq!(mapped.results, vec!["ord_101", "ord_102", "ord_103"]);
    }

    #[test]
    fn tc_1_3_4_paginated_response_empty_and_default() {
        let empty: PaginatedResponse<String> = PaginatedResponse::default();
        assert_eq!(empty.count, 0);
        assert!(!empty.has_next());
        assert!(!empty.has_previous());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.next_page_number(), None);
        assert_eq!(empty.previous_page_number(), None);
    }

    #[test]
    fn tc_1_3_4_paginated_response_malformed_urls_and_json() {
        let resp = PaginatedResponse {
            count: 1,
            next: Some("not a valid url".to_string()),
            previous: Some("https://accept.paymob.com/api/orders?page=abc".to_string()),
            results: vec![1_u8],
        };
        assert_eq!(resp.next_page_number(), None);
        assert_eq!(resp.previous_page_number(), None);

        let missing_param = PaginatedResponse::<u8> {
            count: 1,
            next: Some("https://accept.paymob.com/api/orders?limit=10".to_string()),
            previous: None,
            results: vec![],
        };
        assert_eq!(missing_param.next_page_number(), None);

        let bad_json = serde_json::from_str::<PaginatedResponse<u8>>(r#"{"count":"bad"}"#);
        assert!(bad_json.is_err());
    }

    #[test]
    fn tc_1_3_4_page_query_builder_and_serialization() {
        let default_q = PageQuery::default();
        assert_eq!(default_q.page(), 1);
        assert_eq!(default_q.page_size(), None);
        assert_eq!(default_q.to_query_string(), "?page=1");
        assert_eq!(default_q.to_string(), "?page=1");
        assert_eq!(default_q.to_query_pairs(), vec![("page", "1".to_string())]);

        let custom_q = PageQuery::new(2).with_page(4).with_page_size(50);
        assert_eq!(custom_q.page(), 4);
        assert_eq!(custom_q.page_size(), Some(50));
        assert_eq!(custom_q.to_query_string(), "?page=4&page_size=50");
        assert_eq!(
            custom_q.to_query_pairs(),
            vec![("page", "4".to_string()), ("page_size", "50".to_string())]
        );

        let next_q = custom_q.next_page();
        assert_eq!(next_q.page(), 5);
        assert_eq!(next_q.page_size(), Some(50));
    }

    #[test]
    fn tc_1_3_4_page_query_boundary_clamping_and_serde() {
        let zero_q = PageQuery::new(0).with_page_size(0);
        assert_eq!(zero_q.page(), 1);
        assert_eq!(zero_q.page_size(), Some(1));

        let clamped_q = PageQuery::default().with_page(0);
        assert_eq!(clamped_q.page(), 1);

        let max_q = PageQuery::new(u32::MAX).next_page();
        assert_eq!(max_q.page(), u32::MAX);

        let serialized = serde_json::to_string(&PageQuery::new(3)).expect("serialize");
        assert_eq!(serialized, r#"{"page":3}"#);
        let roundtrip: PageQuery = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(roundtrip, PageQuery::new(3));
    }
}
