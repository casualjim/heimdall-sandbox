//! Overlapping token window planning for inputs longer than a model's context.

use crate::{Error, Result};

const DEFAULT_WINDOW_OVERLAP_TOKENS: usize = 256;

/// A half-open token range `[start, end)` of one source sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenWindow {
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

    /// Index of the input sequence this window was cut from.
    #[must_use]
    pub const fn source_sequence(self) -> usize {
        self.source_sequence
    }

    /// First token of the window within its source sequence.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// One past the last token of the window within its source sequence.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Split sequences longer than `usable_token_limit` into overlapping windows.
///
/// Sequences that fit stay a single window. Longer sequences advance so that
/// consecutive windows overlap by up to 256 tokens (less for small limits) and
/// the final window ends at the last token.
pub fn plan_token_windows(
    lengths: &[usize],
    usable_token_limit: usize,
) -> Result<Vec<TokenWindow>> {
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
                return Err(Error::InvalidInput {
                    detail: "token window plan cannot make forward progress".to_string(),
                });
            }
            start = next_start;
        }
    }

    Ok(windows)
}

fn window_overlap(usable_token_limit: usize) -> Result<usize> {
    if usable_token_limit < 3 {
        return Err(Error::InvalidInput {
            detail: format!(
                "usable token limit {usable_token_limit} is too small for overlapping windows"
            ),
        });
    }
    Ok(DEFAULT_WINDOW_OVERLAP_TOKENS.min((usable_token_limit - 1) / 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_keeps_single_window_input_unchanged() {
        let windows = plan_token_windows(&[5], 8).unwrap();
        assert_eq!(windows, vec![TokenWindow::new(0, 0, 5)]);
    }

    #[test]
    fn planner_covers_overflow_with_forward_progress() {
        let windows = plan_token_windows(&[20], 8).unwrap();
        assert_eq!(windows.first().unwrap().start(), 0);
        assert_eq!(windows.last().unwrap().end(), 20);
        for pair in windows.windows(2) {
            assert!(pair[1].start() > pair[0].start());
            assert!(pair[0].end() > pair[1].start());
            assert!(pair[1].start() <= pair[0].end());
        }
        for token in 0..20 {
            assert!(
                windows
                    .iter()
                    .any(|window| token >= window.start() && token < window.end()),
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

    #[test]
    fn planner_stride_matches_limit_minus_overlap() {
        // 510-token windows overlap by 254, so each window advances by 256.
        let windows = plan_token_windows(&[1000], 510).unwrap();
        let starts = windows
            .iter()
            .map(|window| window.start())
            .collect::<Vec<_>>();
        assert_eq!(starts, vec![0, 256, 512]);
        assert_eq!(windows.last().unwrap().end(), 1000);
    }
}
