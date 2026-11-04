use std::ops::Range;

use crate::{Error, Result};

/// Replacement text for spans flagged as prompt injection.
const REDACTION_MARKER: &str = "[REDACTED:prompt-injection]";

/// Result of scanning one text for prompt injection.
#[derive(Clone, Debug, PartialEq)]
pub struct InjectionScan {
    max_margin: Option<f32>,
    threshold: f32,
    spans: Vec<Range<usize>>,
}

impl InjectionScan {
    /// Build a scan from per-window results; overlapping or touching spans are merged.
    pub(crate) fn new(
        max_margin: Option<f32>,
        threshold: f32,
        mut spans: Vec<Range<usize>>,
    ) -> Self {
        spans.sort_by_key(|span| span.start);
        let mut merged: Vec<Range<usize>> = Vec::with_capacity(spans.len());
        for span in spans {
            match merged.last_mut() {
                Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
                _ => merged.push(span),
            }
        }
        Self {
            max_margin,
            threshold,
            spans: merged,
        }
    }

    /// Whether any window scored at or above the margin threshold.
    #[must_use]
    pub fn is_flagged(&self) -> bool {
        !self.spans.is_empty()
    }

    /// Highest window margin, or `None` when the text had no tokens.
    #[must_use]
    pub const fn max_margin(&self) -> Option<f32> {
        self.max_margin
    }

    /// Margin at or above which a window is flagged.
    #[must_use]
    pub const fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Flagged byte ranges of the scanned text, sorted and non-overlapping.
    #[must_use]
    pub fn spans(&self) -> &[Range<usize>] {
        &self.spans
    }

    /// Replace flagged spans of `text` with a redaction marker.
    ///
    /// `text` must be the string that was scanned.
    pub fn redact(&self, text: &str) -> Result<String> {
        let mut redacted = String::with_capacity(text.len());
        let mut cursor = 0;
        for span in &self.spans {
            let kept = text.get(cursor..span.start).ok_or_else(|| Error::Decode {
                detail: "flagged span does not match the supplied text".to_string(),
            })?;
            redacted.push_str(kept);
            redacted.push_str(REDACTION_MARKER);
            cursor = span.end;
        }
        let rest = text.get(cursor..).ok_or_else(|| Error::Decode {
            detail: "flagged span does not match the supplied text".to_string(),
        })?;
        redacted.push_str(rest);
        Ok(redacted)
    }
}

#[cfg(test)]
mod tests {
    use std::iter::once;

    use super::*;

    #[test]
    fn overlapping_and_touching_spans_merge() {
        let scan = InjectionScan::new(Some(5.0), 3.9, vec![10..20, 0..4, 4..6, 15..30]);
        assert_eq!(scan.spans(), [0..6, 10..30]);
        assert!(scan.is_flagged());
    }

    #[test]
    fn redact_replaces_only_flagged_spans() {
        let text = "hello EVIL INSTRUCTION world";
        let scan = InjectionScan::new(Some(5.0), 3.9, once(6..22).collect());
        assert_eq!(
            scan.redact(text).unwrap(),
            "hello [REDACTED:prompt-injection] world"
        );
    }

    #[test]
    fn unflagged_scan_redacts_to_identity() {
        let scan = InjectionScan::new(Some(-2.0), 3.9, vec![]);
        assert!(!scan.is_flagged());
        assert_eq!(scan.redact("same").unwrap(), "same");
    }

    #[test]
    fn redact_rejects_spans_outside_the_text() {
        let scan = InjectionScan::new(Some(5.0), 3.9, once(2..50).collect());
        assert!(scan.redact("short").is_err());
    }
}
