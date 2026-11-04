use std::ops::Range;

/// Whitespace-flattened text that can map byte ranges back to the original.
///
/// The classifier is evaluated on text with whitespace runs collapsed to one
/// space. Every word is copied unchanged, so a byte offset inside a flattened
/// word maps to the same offset inside the original word.
pub(crate) struct FlatText {
    text: String,
    words: Vec<Word>,
}

struct Word {
    flat_start: usize,
    original_start: usize,
    len: usize,
}

impl FlatText {
    pub(crate) fn new(original: &str) -> Self {
        let mut text = String::with_capacity(original.len());
        let mut words = Vec::new();
        let mut word_start = None;

        for (index, ch) in original.char_indices().chain([(original.len(), ' ')]) {
            match (word_start, ch.is_whitespace()) {
                (None, false) => word_start = Some(index),
                (Some(start), true) => {
                    if !text.is_empty() {
                        text.push(' ');
                    }
                    words.push(Word {
                        flat_start: text.len(),
                        original_start: start,
                        len: index - start,
                    });
                    text.push_str(&original[start..index]);
                    word_start = None;
                }
                _ => {}
            }
        }

        Self { text, words }
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Map a non-empty flattened byte range to the original text.
    ///
    /// Boundaries that fall on a collapsed space snap inward to the nearest word.
    /// Returns `None` when the range covers no word bytes.
    pub(crate) fn original_range(&self, flat: Range<usize>) -> Option<Range<usize>> {
        let first = self.words.get(
            self.words
                .partition_point(|w| w.flat_start + w.len <= flat.start),
        )?;
        let last = self.words.get(
            self.words
                .partition_point(|w| w.flat_start < flat.end)
                .checked_sub(1)?,
        )?;

        let start = first.original_start + flat.start.saturating_sub(first.flat_start);
        let end = last.original_start + flat.end.min(last.flat_start + last.len) - last.flat_start;
        (start < end).then_some(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_whitespace_and_trims() {
        let flat = FlatText::new("  ignore \n\t previous   instructions \n");
        assert_eq!(flat.text(), "ignore previous instructions");
    }

    #[test]
    fn maps_ranges_back_across_collapsed_whitespace() {
        let original = "a  ignore \n previous   b";
        let flat = FlatText::new(original);
        assert_eq!(flat.text(), "a ignore previous b");
        let range = flat.original_range(2..17).unwrap();
        assert_eq!(&original[range], "ignore \n previous");
    }

    #[test]
    fn range_on_a_collapsed_space_snaps_to_words() {
        let original = "one   two";
        let flat = FlatText::new(original);
        assert!(flat.original_range(3..4).is_none());
        let range = flat.original_range(3..8).unwrap();
        assert_eq!(&original[range], "two");
    }

    #[test]
    fn multibyte_words_map_on_char_boundaries() {
        let original = "héllo   wörld";
        let flat = FlatText::new(original);
        let range = flat.original_range(0..flat.text().len()).unwrap();
        assert_eq!(&original[range], original);
    }

    #[test]
    fn empty_and_blank_inputs_have_no_words() {
        assert_eq!(FlatText::new("").text(), "");
        assert!(FlatText::new(" \n ").original_range(0..1).is_none());
    }
}
