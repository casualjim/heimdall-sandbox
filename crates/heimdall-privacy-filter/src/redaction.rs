use crate::Result;
use crate::output::DetectedSpan;
use crate::runtime::PrivacyFilterRuntime;

/// Raw local output plus redacted model-facing output for a captured text value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedTextRedaction {
    /// Unmodified captured text that may be shown to the trusted local user/UI.
    pub raw_for_user: String,
    /// Redacted text that may be sent to the LLM/model context.
    pub redacted_for_llm: String,
}

/// Redact one captured text value while preserving the raw local copy.
pub fn redact_captured_text(
    runtime: &mut PrivacyFilterRuntime,
    raw_for_user: impl Into<String>,
) -> Result<CapturedTextRedaction> {
    let raw_for_user = raw_for_user.into();
    let redacted_for_llm = redact_text(runtime, &raw_for_user)?;
    Ok(CapturedTextRedaction {
        raw_for_user,
        redacted_for_llm,
    })
}

/// Redact one captured text value for model-facing use.
pub fn redact_text(runtime: &mut PrivacyFilterRuntime, text: &str) -> Result<String> {
    let output = runtime.detect_spans(text)?;
    Ok(apply_spans(text, output.spans))
}

fn apply_spans(text: &str, mut spans: Vec<DetectedSpan>) -> String {
    spans.sort_by_key(|span| (span.start(), span.end()));
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;

    for span in spans {
        let start = span.start();
        let end = span.end();
        if start < cursor || end <= cursor || start >= end || end > text.len() {
            continue;
        }
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        redacted.push_str(&text[cursor..start]);
        redacted.push_str("[REDACTED:");
        redacted.push_str(span.label());
        redacted.push(']');
        cursor = end;
    }

    redacted.push_str(&text[cursor..]);
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    // --- apply_spans adversarial (no model needed) ---

    #[test]
    fn apply_spans_overlapping_spans_first_wins() {
        let text = "abcdefghij";
        let spans = vec![
            DetectedSpan::new(0, 0, 5, "A".to_string(), 1.0),
            DetectedSpan::new(0, 3, 8, "B".to_string(), 1.0),
        ];
        let result = apply_spans(text, spans);
        assert_eq!(result, "[REDACTED:A]fghij");
    }

    #[test]
    fn apply_spans_zero_length_span_is_skipped() {
        let text = "hello";
        let spans = vec![DetectedSpan::new(0, 2, 2, "X".to_string(), 1.0)];
        let result = apply_spans(text, spans);
        assert_eq!(result, "hello");
    }

    #[test]
    fn apply_spans_span_past_end_is_skipped() {
        let text = "hi";
        let spans = vec![DetectedSpan::new(0, 0, 99, "X".to_string(), 1.0)];
        let result = apply_spans(text, spans);
        assert_eq!(result, "hi");
    }

    #[test]
    fn apply_spans_non_char_boundary_is_skipped() {
        // "ü" is 2 bytes. Split at byte 1 = not a char boundary.
        let text = "aüb";
        let spans = vec![DetectedSpan::new(0, 1, 2, "X".to_string(), 1.0)];
        let result = apply_spans(text, spans);
        assert_eq!(result, "aüb");
    }

    #[test]
    fn apply_spans_out_of_order_gets_sorted() {
        let text = "abcdefghij";
        let spans = vec![
            DetectedSpan::new(0, 5, 10, "B".to_string(), 1.0),
            DetectedSpan::new(0, 0, 5, "A".to_string(), 1.0),
        ];
        let result = apply_spans(text, spans);
        assert_eq!(result, "[REDACTED:A][REDACTED:B]");
    }

    #[test]
    fn apply_spans_empty_spans_returns_original() {
        let result = apply_spans("hello", vec![]);
        assert_eq!(result, "hello");
    }

    // --- real model ---

    #[test]
    fn redact_email_with_real_model() {
        let f = testutil::fixture();
        let mut runtime = crate::runtime::PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let result = redact_text(&mut runtime, "My email is alice@example.com").unwrap();
        assert!(result.contains("[REDACTED:"));
        assert!(!result.contains("alice@example.com"));
    }

    #[test]
    fn redact_captured_preserves_raw() {
        let f = testutil::fixture();
        let mut runtime = crate::runtime::PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let captured = redact_captured_text(&mut runtime, "bob@company.org").unwrap();
        assert_eq!(captured.raw_for_user, "bob@company.org");
        assert_ne!(captured.redacted_for_llm, captured.raw_for_user);
    }

    #[test]
    fn redact_empty_string_errors_not_panics() {
        let f = testutil::fixture();
        let mut runtime = crate::runtime::PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let result = redact_text(&mut runtime, "");
        assert!(result.is_err(), "empty string must error, not panic");
    }
}
