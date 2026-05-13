use ndarray::{Array, Array2, ArrayView};
use tokenizers::Tokenizer;

use crate::{Error, Result};

const DEFAULT_WINDOW_OVERLAP_TOKENS: usize = 256;

impl From<ndarray::ShapeError> for Error {
    fn from(error: ndarray::ShapeError) -> Self {
        Self::Decode {
            detail: format!("tensor shape error: {error}"),
        }
    }
}

/// Raw text input for privacy-filter detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyTextInput {
    texts: Vec<String>,
}

impl PrivacyTextInput {
    /// Create text input from one or more text windows.
    pub fn new(texts: Vec<String>) -> Result<Self> {
        if texts.is_empty() {
            return Err(Error::InvalidAsset {
                detail: "privacy filter input cannot be empty".to_string(),
            });
        }
        Ok(Self { texts })
    }

    /// Create text input for a single text window.
    pub fn single(text: impl Into<String>) -> Result<Self> {
        Self::new(vec![text.into()])
    }

    /// Return the raw text windows.
    #[must_use]
    pub fn texts(&self) -> &[String] {
        &self.texts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TokenWindow {
    source_sequence: usize,
    start: usize,
    end: usize,
}

impl TokenWindow {
    const fn new(source_sequence: usize, start: usize, end: usize) -> Self {
        Self {
            source_sequence,
            start,
            end,
        }
    }
}

pub(crate) fn plan_token_windows(
    lengths: &[usize],
    usable_token_limit: usize,
) -> Result<Vec<TokenWindow>> {
    if usable_token_limit == 0 {
        return Err(Error::InvalidAsset {
            detail: "privacy filter usable token limit must be greater than zero".to_string(),
        });
    }
    let overlap = window_overlap(usable_token_limit)?;
    let mut windows = Vec::new();

    for (source_sequence, length) in lengths.iter().copied().enumerate() {
        if length <= usable_token_limit {
            windows.push(TokenWindow::new(source_sequence, 0, length));
            continue;
        }

        let mut start = 0;
        while start < length {
            let end = (start + usable_token_limit).min(length);
            windows.push(TokenWindow::new(source_sequence, start, end));
            if end == length {
                break;
            }
            let next_start = end - overlap;
            if next_start <= start {
                return Err(Error::InvalidAsset {
                    detail: "privacy filter token window plan cannot make forward progress"
                        .to_string(),
                });
            }
            start = next_start;
        }
    }

    Ok(windows)
}

fn window_overlap(usable_token_limit: usize) -> Result<usize> {
    if usable_token_limit < 3 {
        return Err(Error::InvalidAsset {
            detail: format!(
                "privacy filter usable token limit {usable_token_limit} is too small for overlapping windows"
            ),
        });
    }
    Ok(DEFAULT_WINDOW_OVERLAP_TOKENS.min((usable_token_limit - 1) / 2))
}

/// Token context preserved from preprocessing through output decoding.
#[derive(Clone, Debug)]
pub(crate) struct PrivacyContext {
    token_offsets: Vec<Vec<(usize, usize)>>,
    source_sequences: Vec<usize>,
}

impl PrivacyContext {
    /// Construct a context directly from texts and token offsets (test only).
    #[cfg(test)]
    pub(crate) fn new_test(_texts: Vec<String>, token_offsets: Vec<Vec<(usize, usize)>>) -> Self {
        let source_sequences = (0..token_offsets.len()).collect();
        Self {
            token_offsets,
            source_sequences,
        }
    }

    #[cfg(test)]
    pub(crate) fn token_offsets_for_test(&self, sequence: usize) -> Option<&[(usize, usize)]> {
        self.token_offsets.get(sequence).map(Vec::as_slice)
    }
}

impl PrivacyContext {
    /// Resolve a token span into byte offsets, skipping special-token zero offsets.
    pub(crate) fn byte_span(
        &self,
        sequence: usize,
        start_token: usize,
        end_token: usize,
    ) -> Result<Option<(usize, usize)>> {
        let offsets = self
            .token_offsets
            .get(sequence)
            .ok_or_else(|| Error::Decode {
                detail: format!("sequence {sequence} is missing from context"),
            })?;
        let mut start = None;
        let mut end = None;
        for index in start_token..=end_token {
            let (token_start, token_end) = *offsets.get(index).ok_or_else(|| Error::Decode {
                detail: format!("token {index} is missing from context"),
            })?;
            if token_start == token_end {
                continue;
            }
            start.get_or_insert(token_start);
            end = Some(token_end);
        }
        Ok(start.zip(end))
    }

    pub(crate) fn source_sequence(&self, sequence: usize) -> Result<usize> {
        self.source_sequences
            .get(sequence)
            .copied()
            .ok_or_else(|| Error::Decode {
                detail: format!("sequence {sequence} source is missing from context"),
            })
    }
}

/// Encoded tensors for ONNX Runtime inference plus decoding context.
#[derive(Clone, Debug)]
pub struct EncodedPrivacyInput {
    /// Input IDs tensor with shape `[B, T]`.
    pub input_ids: Array2<i64>,
    /// Attention mask tensor with shape `[B, T]`.
    pub attention_mask: Array2<i64>,
    /// Context needed to convert token predictions back to text spans.
    pub(crate) context: PrivacyContext,
}

impl EncodedPrivacyInput {
    /// Encode privacy-filter input using the local tokenizer.
    pub fn encode(
        input: PrivacyTextInput,
        tokenizer: &Tokenizer,
        pad_token_id: i64,
        usable_token_limit: usize,
    ) -> Result<Self> {
        let mut full_rows = Vec::with_capacity(input.texts.len());
        let mut full_masks = Vec::with_capacity(input.texts.len());
        let mut full_offsets = Vec::with_capacity(input.texts.len());

        for text in input.texts() {
            let encoding = tokenizer.encode(text.as_str(), true)?;
            full_rows.push(
                encoding
                    .get_ids()
                    .iter()
                    .map(|id| i64::from(*id))
                    .collect::<Vec<_>>(),
            );
            full_masks.push(
                encoding
                    .get_attention_mask()
                    .iter()
                    .map(|value| i64::from(*value))
                    .collect::<Vec<_>>(),
            );
            full_offsets.push(encoding.get_offsets().to_vec());
        }

        let lengths = full_rows.iter().map(Vec::len).collect::<Vec<_>>();
        let windows = plan_token_windows(&lengths, usable_token_limit)?;
        let mut rows = Vec::with_capacity(windows.len());
        let mut masks = Vec::with_capacity(windows.len());
        let mut token_offsets = Vec::with_capacity(windows.len());
        let mut source_sequences = Vec::with_capacity(windows.len());
        let mut max_len = 0;

        for window in windows {
            let ids = full_rows[window.source_sequence][window.start..window.end].to_vec();
            let attention = full_masks[window.source_sequence][window.start..window.end].to_vec();
            let offsets = full_offsets[window.source_sequence][window.start..window.end].to_vec();
            max_len = max_len.max(ids.len());
            rows.push(ids);
            masks.push(attention);
            token_offsets.push(offsets);
            source_sequences.push(window.source_sequence);
        }

        let mut input_ids = Array::zeros((0, max_len));
        let mut attention_mask = Array::zeros((0, max_len));
        for (mut ids, mut mask) in rows.into_iter().zip(masks) {
            ids.resize(max_len, pad_token_id);
            mask.resize(max_len, 0);
            input_ids.push_row(ArrayView::from(&ids))?;
            attention_mask.push_row(ArrayView::from(&mask))?;
        }

        Ok(Self {
            input_ids,
            attention_mask,
            context: PrivacyContext {
                token_offsets,
                source_sequences,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn single_rejects_empty_string_vec() {
        assert!(PrivacyTextInput::new(vec![]).is_err());
    }

    #[test]
    fn single_accepts_one_text() {
        let input = PrivacyTextInput::single("hello").unwrap();
        assert_eq!(input.texts(), &["hello".to_string()]);
    }

    #[test]
    fn byte_span_skips_zero_offsets() {
        let ctx =
            PrivacyContext::new_test(vec!["ab".to_string()], vec![vec![(0, 0), (0, 2), (0, 0)]]);
        let span = ctx.byte_span(0, 0, 2).unwrap();
        assert_eq!(span, Some((0, 2)));
    }

    #[test]
    fn byte_span_returns_none_when_all_zero_offsets() {
        let ctx = PrivacyContext::new_test(vec!["".to_string()], vec![vec![(0, 0), (0, 0)]]);
        let span = ctx.byte_span(0, 0, 1).unwrap();
        assert!(span.is_none());
    }

    #[test]
    fn byte_span_rejects_out_of_range_sequence() {
        let ctx = PrivacyContext::new_test(vec!["a".to_string()], vec![vec![(0, 1)]]);
        assert!(ctx.byte_span(99, 0, 0).is_err());
    }

    #[test]
    fn byte_span_rejects_out_of_range_token() {
        let ctx = PrivacyContext::new_test(vec!["a".to_string()], vec![vec![(0, 1)]]);
        assert!(ctx.byte_span(0, 0, 99).is_err());
    }

    #[test]
    fn planner_keeps_single_window_input_unchanged() {
        let windows = plan_token_windows(&[5], 8).unwrap();
        assert_eq!(windows, vec![TokenWindow::new(0, 0, 5)]);
    }

    #[test]
    fn planner_covers_overflow_with_forward_progress() {
        let windows = plan_token_windows(&[20], 8).unwrap();
        assert_eq!(windows.first().unwrap().start, 0);
        assert_eq!(windows.last().unwrap().end, 20);
        for pair in windows.windows(2) {
            assert!(pair[1].start > pair[0].start);
            assert!(pair[0].end > pair[1].start);
            assert!(pair[1].start <= pair[0].end);
        }
        for token in 0..20 {
            assert!(
                windows
                    .iter()
                    .any(|window| token >= window.start && token < window.end),
                "token {token} not covered"
            );
        }
    }

    #[test]
    fn planner_rejects_unusable_limit() {
        assert!(plan_token_windows(&[3], 0).is_err());
        assert!(plan_token_windows(&[3], 1).is_err());
        assert!(plan_token_windows(&[3], 2).is_err());
    }

    // --- real tokenizer ---

    #[test]
    fn encode_single_produces_1_row() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let input = PrivacyTextInput::single("hello world").unwrap();
        let encoded = EncodedPrivacyInput::encode(
            input,
            &tokenizer,
            f.labels.pad_token_id(),
            f.usable_token_limit,
        )
        .unwrap();
        assert_eq!(encoded.input_ids.nrows(), 1);
        assert_eq!(encoded.attention_mask.nrows(), 1);
        assert_eq!(encoded.input_ids.ncols(), encoded.attention_mask.ncols());
    }

    #[test]
    fn encode_batch_pads_to_max() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let input = PrivacyTextInput::new(vec![
            "short".to_string(),
            "a much longer sentence here".to_string(),
        ])
        .unwrap();
        let encoded = EncodedPrivacyInput::encode(
            input,
            &tokenizer,
            f.labels.pad_token_id(),
            f.usable_token_limit,
        )
        .unwrap();
        assert_eq!(encoded.input_ids.nrows(), 2);
        assert_eq!(encoded.attention_mask.nrows(), 2);
        let cols = encoded.input_ids.ncols();
        assert!(cols > 0);
        let first_mask = encoded.attention_mask.row(0).to_vec();
        assert!(first_mask.contains(&0), "padded tokens must have mask=0");
    }

    #[test]
    fn encode_produces_valid_offsets() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let input = PrivacyTextInput::single("test text").unwrap();
        let encoded = EncodedPrivacyInput::encode(
            input,
            &tokenizer,
            f.labels.pad_token_id(),
            f.usable_token_limit,
        )
        .unwrap();
        assert!(!encoded.context.token_offsets.is_empty());
    }

    #[test]
    fn real_tokenizer_adds_no_special_zero_offset_tokens() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let encoding = tokenizer.encode("hello world", true).unwrap();
        assert!(
            encoding
                .get_offsets()
                .iter()
                .all(|(start, end)| start < end)
        );
    }

    #[test]
    fn encode_overflow_preserves_original_utf8_offsets() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let text = "alpha ümlaut beta gamma delta epsilon zeta eta theta";
        let input = PrivacyTextInput::single(text).unwrap();
        let encoded =
            EncodedPrivacyInput::encode(input, &tokenizer, f.labels.pad_token_id(), 8).unwrap();
        assert!(encoded.input_ids.nrows() > 1);
        let mut saw_umlaut = false;
        for sequence in 0..encoded.input_ids.nrows() {
            for &(start, end) in encoded.context.token_offsets_for_test(sequence).unwrap() {
                if start == end {
                    continue;
                }
                assert!(text.is_char_boundary(start));
                assert!(text.is_char_boundary(end));
                if text[start..end].contains('ü') {
                    saw_umlaut = true;
                }
            }
        }
        assert!(saw_umlaut);
    }
}
