use ndarray::{Array, Array2, ArrayView};
use tokenizers::Tokenizer;

use crate::{Error, Result};

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

/// Token context preserved from preprocessing through output decoding.
#[derive(Clone, Debug)]
pub(crate) struct PrivacyContext {
    token_offsets: Vec<Vec<(usize, usize)>>,
}

impl PrivacyContext {
    /// Construct a context directly from texts and token offsets (test only).
    #[cfg(test)]
    pub(crate) fn new_test(_texts: Vec<String>, token_offsets: Vec<Vec<(usize, usize)>>) -> Self {
        Self { token_offsets }
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
}

/// Encoded tensors for ONNX Runtime inference plus decoding context.
#[derive(Clone, Debug)]
pub struct EncodedPrivacyInput {
    /// Input IDs tensor with shape `[B, T]`.
    pub input_ids: Array2<i64>,
    /// Attention mask tensor with shape `[B, T]`.
    pub attention_mask: Array2<i64>,
    /// Context needed to convert token predictions back to text spans.
    pub context: PrivacyContext,
}

impl EncodedPrivacyInput {
    /// Encode privacy-filter input using the local tokenizer.
    pub fn encode(
        input: PrivacyTextInput,
        tokenizer: &Tokenizer,
        pad_token_id: i64,
    ) -> Result<Self> {
        let mut rows = Vec::with_capacity(input.texts.len());
        let mut masks = Vec::with_capacity(input.texts.len());
        let mut token_offsets = Vec::with_capacity(input.texts.len());
        let mut max_len = 0;

        for text in input.texts() {
            let encoding = tokenizer.encode(text.as_str(), true)?;
            let ids = encoding
                .get_ids()
                .iter()
                .map(|id| i64::from(*id))
                .collect::<Vec<_>>();
            let attention = encoding
                .get_attention_mask()
                .iter()
                .map(|value| i64::from(*value))
                .collect::<Vec<_>>();
            max_len = max_len.max(ids.len());
            rows.push(ids);
            masks.push(attention);
            token_offsets.push(encoding.get_offsets().to_vec());
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
            context: PrivacyContext { token_offsets },
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

    // --- real tokenizer ---

    #[test]
    fn encode_single_produces_1_row() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let input = PrivacyTextInput::single("hello world").unwrap();
        let encoded =
            EncodedPrivacyInput::encode(input, &tokenizer, f.labels.pad_token_id()).unwrap();
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
        let encoded =
            EncodedPrivacyInput::encode(input, &tokenizer, f.labels.pad_token_id()).unwrap();
        assert_eq!(encoded.input_ids.nrows(), 2);
        assert_eq!(encoded.attention_mask.nrows(), 2);
        let cols = encoded.input_ids.ncols();
        assert!(cols > 0);
        // Short text should have trailing zeros in its mask.
        let first_mask = encoded.attention_mask.row(0).to_vec();
        assert!(first_mask.contains(&0), "padded tokens must have mask=0");
    }

    #[test]
    fn encode_produces_valid_offsets() {
        let f = testutil::fixture();
        let tokenizer = Tokenizer::from_file(&f.assets.tokenizer).unwrap();
        let input = PrivacyTextInput::single("test text").unwrap();
        let encoded =
            EncodedPrivacyInput::encode(input, &tokenizer, f.labels.pad_token_id()).unwrap();
        assert!(!encoded.context.token_offsets.is_empty());
    }
}
