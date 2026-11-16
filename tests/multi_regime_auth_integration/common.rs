use std::fmt;

pub fn assert_redacted_debug<T: fmt::Debug>(value: &T, secrets: &[&str], expect_marker: bool) {
    let rendered = format!("{value:?}");
    for secret in secrets {
        assert!(!rendered.contains(secret), "Debug output leaked secret");
    }
    if expect_marker {
        assert!(
            rendered.contains("REDACTED"),
            "Debug output missing redaction marker: {rendered}"
        );
    }
}
