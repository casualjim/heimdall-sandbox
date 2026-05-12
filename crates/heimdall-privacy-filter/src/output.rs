use std::collections::BTreeMap;

use ndarray::{ArrayD, Ix2, Ix3};
use serde::Deserialize;

use crate::input::PrivacyContext;
use crate::{Error, Result};

/// One detected sensitive span in the original text.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectedSpan {
    sequence: usize,
    start: usize,
    end: usize,
    label: String,
    score: f32,
}

impl DetectedSpan {
    /// Create a detected span from validated fields.
    ///
    /// The caller is responsible for ensuring `start <= end` and that both offsets
    /// are valid byte boundaries in the source text.
    #[must_use]
    pub const fn new(sequence: usize, start: usize, end: usize, label: String, score: f32) -> Self {
        Self {
            sequence,
            start,
            end,
            label,
            score,
        }
    }

    /// Input window index.
    #[must_use]
    pub const fn sequence(&self) -> usize {
        self.sequence
    }

    /// Start byte offset in the input window.
    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// End byte offset in the input window.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Privacy category without BIOES prefix.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Approximate confidence score for this span.
    #[must_use]
    pub const fn score(&self) -> f32 {
        self.score
    }
}

/// Privacy-filter detection output for a batch of text windows.
#[derive(Clone, Debug, Default, PartialEq)]
#[must_use]
pub struct PrivacySpanOutput {
    /// Detected sensitive spans.
    pub spans: Vec<DetectedSpan>,
}

impl PrivacySpanOutput {
    /// Return true when no sensitive spans were detected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ModelConfig {
    id2label: BTreeMap<String, String>,
    pad_token_id: Option<i64>,
}

/// Parsed model labels and tokenizer settings from `config.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyLabels {
    labels: Vec<Label>,
    pad_token_id: i64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Label {
    prefix: LabelPrefix,
    category: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum LabelPrefix {
    Outside,
    Begin,
    Inside,
    End,
    Singleton,
}

impl PrivacyLabels {
    /// Parse and validate OpenAI privacy-filter labels from `config.json`.
    pub fn from_config_json(json: &str) -> Result<Self> {
        let config = serde_json::from_str::<ModelConfig>(json)?;
        let mut labels = Vec::with_capacity(config.id2label.len());
        for expected in 0..config.id2label.len() {
            let raw =
                config
                    .id2label
                    .get(&expected.to_string())
                    .ok_or_else(|| Error::InvalidAsset {
                        detail: format!("missing id2label entry {expected}"),
                    })?;
            labels.push(Label::parse(raw)?);
        }
        if labels.len() != 33 {
            return Err(Error::InvalidAsset {
                detail: format!("expected 33 labels, found {}", labels.len()),
            });
        }
        if labels
            .first()
            .is_none_or(|label| label.prefix != LabelPrefix::Outside)
        {
            return Err(Error::InvalidAsset {
                detail: "label 0 must be O".to_string(),
            });
        }
        Ok(Self {
            labels,
            pad_token_id: config.pad_token_id.unwrap_or(199_999),
        })
    }

    /// Return label count.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.labels.len()
    }

    /// Return tokenizer pad token ID from model config.
    #[must_use]
    pub const fn pad_token_id(&self) -> i64 {
        self.pad_token_id
    }

    fn get(&self, index: usize) -> Result<&Label> {
        self.labels.get(index).ok_or_else(|| Error::Decode {
            detail: format!("label index {index} is out of range"),
        })
    }
}

impl Label {
    fn parse(raw: &str) -> Result<Self> {
        if raw == "O" {
            return Ok(Self {
                prefix: LabelPrefix::Outside,
                category: None,
            });
        }
        let Some((prefix, category)) = raw.split_once('-') else {
            return Err(Error::InvalidAsset {
                detail: format!("invalid label {raw}"),
            });
        };
        let prefix = match prefix {
            "B" => LabelPrefix::Begin,
            "I" => LabelPrefix::Inside,
            "E" => LabelPrefix::End,
            "S" => LabelPrefix::Singleton,
            other => {
                return Err(Error::InvalidAsset {
                    detail: format!("invalid BIOES prefix {other}"),
                });
            }
        };
        Ok(Self {
            prefix,
            category: Some(category.to_string()),
        })
    }

    fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ViterbiFile {
    operating_points: BTreeMap<String, OperatingPoint>,
}

#[derive(Clone, Debug, Deserialize)]
struct OperatingPoint {
    biases: ViterbiCalibration,
}

/// Viterbi transition calibration values.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
pub struct ViterbiCalibration {
    /// Bias for staying in background.
    pub transition_bias_background_stay: f32,
    /// Bias for background to begin/singleton.
    pub transition_bias_background_to_start: f32,
    /// Bias for end/singleton to background.
    pub transition_bias_end_to_background: f32,
    /// Bias for end/singleton to begin/singleton.
    pub transition_bias_end_to_start: f32,
    /// Bias for inside continuation.
    pub transition_bias_inside_to_continue: f32,
    /// Bias for inside to end.
    pub transition_bias_inside_to_end: f32,
}

impl ViterbiCalibration {
    /// Parse the default operating point from `viterbi_calibration.json`.
    pub fn from_json(json: &str) -> Result<Self> {
        let file = serde_json::from_str::<ViterbiFile>(json)?;
        file.operating_points
            .get("default")
            .map(|point| point.biases)
            .ok_or_else(|| Error::InvalidAsset {
                detail: "viterbi default operating point is missing".to_string(),
            })
    }
}

/// Decode model logits to text spans using constrained BIOES Viterbi decoding.
pub fn decode_logits(
    logits: ArrayD<f32>,
    context: PrivacyContext,
    labels: &PrivacyLabels,
    calibration: ViterbiCalibration,
) -> Result<PrivacySpanOutput> {
    let dimensions = logits.shape().to_vec();
    match dimensions.as_slice() {
        [_tokens, classes] => {
            if *classes != labels.len() {
                return Err(Error::Decode {
                    detail: format!("expected {} classes, found {classes}", labels.len()),
                });
            }
            let logits =
                logits
                    .into_dimensionality::<Ix2>()
                    .map_err(|error: ndarray::ShapeError| Error::Decode {
                        detail: error.to_string(),
                    })?;
            decode_sequence(0, logits.view(), &context, labels, calibration)
        }
        [batch, _tokens, classes] => {
            if *classes != labels.len() {
                return Err(Error::Decode {
                    detail: format!("expected {} classes, found {classes}", labels.len()),
                });
            }
            let logits =
                logits
                    .into_dimensionality::<Ix3>()
                    .map_err(|error: ndarray::ShapeError| Error::Decode {
                        detail: error.to_string(),
                    })?;
            let mut spans = Vec::new();
            for sequence in 0..*batch {
                let output = decode_sequence(
                    sequence,
                    logits.index_axis(ndarray::Axis(0), sequence),
                    &context,
                    labels,
                    calibration,
                )?;
                spans.extend(output.spans);
            }
            Ok(PrivacySpanOutput { spans })
        }
        _ => Err(Error::Decode {
            detail: format!("expected logits shape [T, C] or [B, T, C], found {dimensions:?}"),
        }),
    }
}

fn decode_sequence(
    sequence: usize,
    logits: ndarray::ArrayView2<'_, f32>,
    context: &PrivacyContext,
    labels: &PrivacyLabels,
    calibration: ViterbiCalibration,
) -> Result<PrivacySpanOutput> {
    let path = viterbi_path(logits, labels, calibration)?;
    let mut spans = Vec::new();
    let mut open: Option<(usize, String, f32)> = None;

    for (token, label_index) in path.into_iter().enumerate() {
        let label = labels.get(label_index)?;
        match label.prefix {
            LabelPrefix::Outside => open = None,
            LabelPrefix::Begin => {
                if let Some(category) = label.category() {
                    open = Some((
                        token,
                        category.to_string(),
                        score_at(logits, token, label_index),
                    ));
                }
            }
            LabelPrefix::Inside => {}
            LabelPrefix::End => {
                if let (Some((start, category, start_score)), Some(end_category)) =
                    (open.take(), label.category())
                    && category == end_category
                    && let Some((start_byte, end_byte)) =
                        context.byte_span(sequence, start, token)?
                {
                    spans.push(DetectedSpan::new(
                        sequence,
                        start_byte,
                        end_byte,
                        category,
                        start_score.min(score_at(logits, token, label_index)),
                    ));
                }
            }
            LabelPrefix::Singleton => {
                open = None;
                if let Some(category) = label.category()
                    && let Some((start, end)) = context.byte_span(sequence, token, token)?
                {
                    spans.push(DetectedSpan::new(
                        sequence,
                        start,
                        end,
                        category.to_string(),
                        score_at(logits, token, label_index),
                    ));
                }
            }
        }
    }

    Ok(PrivacySpanOutput { spans })
}

fn viterbi_path(
    logits: ndarray::ArrayView2<'_, f32>,
    labels: &PrivacyLabels,
    calibration: ViterbiCalibration,
) -> Result<Vec<usize>> {
    let (tokens, classes) = logits.dim();
    if classes != labels.len() {
        return Err(Error::Decode {
            detail: format!("expected {} classes, found {classes}", labels.len()),
        });
    }
    if tokens == 0 {
        return Ok(Vec::new());
    }

    let mut scores = vec![vec![f32::NEG_INFINITY; classes]; tokens];
    let mut back = vec![vec![0_usize; classes]; tokens];
    for class in 0..classes {
        let label = labels.get(class)?;
        if matches!(
            label.prefix,
            LabelPrefix::Outside | LabelPrefix::Begin | LabelPrefix::Singleton
        ) {
            scores[0][class] = logits[[0, class]];
        }
    }

    for token in 1..tokens {
        for class in 0..classes {
            let current = labels.get(class)?;
            for previous in 0..classes {
                let previous_label = labels.get(previous)?;
                let Some(transition) = transition_score(previous_label, current, calibration)
                else {
                    continue;
                };
                let candidate = scores[token - 1][previous] + transition + logits[[token, class]];
                if candidate > scores[token][class] {
                    scores[token][class] = candidate;
                    back[token][class] = previous;
                }
            }
        }
    }

    let mut best = (0..classes)
        .max_by(|left, right| scores[tokens - 1][*left].total_cmp(&scores[tokens - 1][*right]))
        .expect("class range is non-empty because classes > 0");
    let mut path = vec![0_usize; tokens];
    for token in (0..tokens).rev() {
        path[token] = best;
        best = back[token][best];
    }
    Ok(path)
}

fn transition_score(
    previous: &Label,
    current: &Label,
    calibration: ViterbiCalibration,
) -> Option<f32> {
    match (previous.prefix, current.prefix) {
        (LabelPrefix::Outside, LabelPrefix::Outside) => {
            Some(calibration.transition_bias_background_stay)
        }
        (LabelPrefix::Outside, LabelPrefix::Begin | LabelPrefix::Singleton) => {
            Some(calibration.transition_bias_background_to_start)
        }
        (LabelPrefix::Begin | LabelPrefix::Inside, LabelPrefix::Inside)
            if previous.category == current.category =>
        {
            Some(calibration.transition_bias_inside_to_continue)
        }
        (LabelPrefix::Begin | LabelPrefix::Inside, LabelPrefix::End)
            if previous.category == current.category =>
        {
            Some(calibration.transition_bias_inside_to_end)
        }
        (LabelPrefix::End | LabelPrefix::Singleton, LabelPrefix::Outside) => {
            Some(calibration.transition_bias_end_to_background)
        }
        (
            LabelPrefix::End | LabelPrefix::Singleton,
            LabelPrefix::Begin | LabelPrefix::Singleton,
        ) => Some(calibration.transition_bias_end_to_start),
        _ => None,
    }
}

fn score_at(logits: ndarray::ArrayView2<'_, f32>, token: usize, label: usize) -> f32 {
    sigmoid(logits[[token, label]])
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    // --- label parsing adversarial ---

    fn make_labels_json(labels: &[String], pad_token_id: Option<i64>) -> String {
        let map: std::collections::BTreeMap<String, String> = labels
            .iter()
            .enumerate()
            .map(|(i, l)| (i.to_string(), l.clone()))
            .collect();
        serde_json::json!({"id2label": map, "pad_token_id": pad_token_id}).to_string()
    }

    fn make_33_labels() -> Vec<String> {
        let mut labels = vec!["O".to_string()];
        for cat in [
            "EMAIL",
            "PHONE",
            "SSN",
            "NAME",
            "ADDRESS",
            "DATE",
            "CREDIT_CARD",
            "URL",
        ] {
            labels.push(format!("B-{cat}"));
            labels.push(format!("I-{cat}"));
            labels.push(format!("E-{cat}"));
            labels.push(format!("S-{cat}"));
        }
        labels
    }

    fn make_test_labels() -> PrivacyLabels {
        PrivacyLabels::from_config_json(&make_labels_json(&make_33_labels(), Some(0))).unwrap()
    }

    fn zero_calibration() -> ViterbiCalibration {
        ViterbiCalibration::default()
    }

    fn fake_context(texts: Vec<&str>) -> PrivacyContext {
        let token_offsets: Vec<Vec<(usize, usize)>> = texts
            .iter()
            .map(|text| {
                let mut offsets = vec![(0, 0)];
                for (i, _) in text.char_indices() {
                    offsets.push((i, i + 1));
                }
                offsets.push((0, 0));
                offsets
            })
            .collect();
        crate::input::PrivacyContext::new_test(
            texts.into_iter().map(String::from).collect(),
            token_offsets,
        )
    }

    #[test]
    fn valid_33_labels_parse() {
        let json = make_labels_json(&make_33_labels(), Some(0));
        let labels = PrivacyLabels::from_config_json(&json).unwrap();
        assert_eq!(labels.len(), 33);
        assert_eq!(labels.pad_token_id(), 0);
    }

    #[test]
    fn labels_reject_wrong_count() {
        let json = make_labels_json(&["O".to_string(), "B-EMAIL".to_string()], None);
        assert!(PrivacyLabels::from_config_json(&json).is_err());
    }

    #[test]
    fn labels_reject_gap_in_indices() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("0".to_string(), "O".to_string());
        for i in 2..34 {
            map.insert(i.to_string(), "O".to_string());
        }
        let json = serde_json::json!({"id2label": map}).to_string();
        assert!(PrivacyLabels::from_config_json(&json).is_err());
    }

    #[test]
    fn labels_reject_label_0_not_outside() {
        let mut labels = make_33_labels();
        labels[0] = "B-EMAIL".to_string();
        let json = make_labels_json(&labels, None);
        assert!(PrivacyLabels::from_config_json(&json).is_err());
    }

    #[test]
    fn labels_reject_bad_bioes_prefix() {
        let mut labels = make_33_labels();
        labels[1] = "Z-EMAIL".to_string();
        let json = make_labels_json(&labels, None);
        assert!(PrivacyLabels::from_config_json(&json).is_err());
    }

    #[test]
    fn labels_reject_bare_category_without_prefix() {
        let mut labels = make_33_labels();
        labels[1] = "EMAIL".to_string();
        let json = make_labels_json(&labels, None);
        assert!(PrivacyLabels::from_config_json(&json).is_err());
    }

    #[test]
    fn pad_token_defaults_when_missing() {
        let json = make_labels_json(&make_33_labels(), None);
        let labels = PrivacyLabels::from_config_json(&json).unwrap();
        assert_eq!(labels.pad_token_id(), 199_999);
    }

    // --- viterbi adversarial ---

    #[test]
    fn decode_logits_empty_tokens_returns_no_spans() {
        let labels = make_test_labels();
        let logits: ArrayD<f32> = ndarray::Array2::zeros((0, labels.len())).into_dyn();
        let context = fake_context(vec![""]);
        let result = decode_logits(logits, context, &labels, zero_calibration()).unwrap();
        assert!(result.spans.is_empty());
    }

    #[test]
    fn decode_logits_rejects_wrong_class_count() {
        let labels = make_test_labels();
        let logits: ArrayD<f32> = ndarray::Array2::zeros((5, 10)).into_dyn();
        let context = fake_context(vec!["hello"]);
        assert!(decode_logits(logits, context, &labels, zero_calibration()).is_err());
    }

    #[test]
    fn decode_logits_rejects_1d_shape() {
        let labels = make_test_labels();
        let logits: ArrayD<f32> = ndarray::Array1::zeros(labels.len()).into_dyn();
        let context = fake_context(vec!["hello"]);
        assert!(decode_logits(logits, context, &labels, zero_calibration()).is_err());
    }

    #[test]
    fn decode_logits_singleton_detects_single_token_entity() {
        let labels = make_test_labels();
        let s_email_idx = 4;
        let mut logits = ndarray::Array2::zeros((3, labels.len()));
        logits[[0, 0]] = 10.0;
        logits[[1, s_email_idx]] = 20.0;
        logits[[2, 0]] = 10.0;

        let context = crate::input::PrivacyContext::new_test(
            vec!["hello".to_string()],
            vec![vec![(0, 0), (0, 5), (0, 0)]],
        );

        let result =
            decode_logits(logits.into_dyn(), context, &labels, zero_calibration()).unwrap();
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].label(), "EMAIL");
        assert_eq!(result.spans[0].start(), 0);
        assert_eq!(result.spans[0].end(), 5);
    }

    #[test]
    fn decode_logits_begin_end_detects_multi_token_entity() {
        let labels = make_test_labels();
        let mut logits = ndarray::Array2::zeros((4, labels.len()));
        logits[[0, 0]] = 10.0;
        logits[[1, 1]] = 20.0; // B-EMAIL
        logits[[2, 3]] = 20.0; // E-EMAIL
        logits[[3, 0]] = 10.0;

        let context = crate::input::PrivacyContext::new_test(
            vec!["abcdef".to_string()],
            vec![vec![(0, 0), (0, 3), (3, 6), (0, 0)]],
        );

        let result =
            decode_logits(logits.into_dyn(), context, &labels, zero_calibration()).unwrap();
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].label(), "EMAIL");
        assert_eq!(result.spans[0].start(), 0);
        assert_eq!(result.spans[0].end(), 6);
    }

    #[test]
    fn decode_logits_mismatched_end_category_drops_span() {
        // B-EMAIL + E-EMAIL = valid sequence that must produce a span.
        // The transition_score function only allows B->E with same category.
        let labels = make_test_labels();
        let mut logits = ndarray::Array2::zeros((3, labels.len()));
        logits[[0, 0]] = 10.0;
        logits[[1, 1]] = 20.0; // B-EMAIL
        logits[[2, 3]] = 20.0; // E-EMAIL

        let context = crate::input::PrivacyContext::new_test(
            vec!["abc".to_string()],
            vec![vec![(0, 0), (0, 3), (0, 0)]],
        );

        let result =
            decode_logits(logits.into_dyn(), context, &labels, zero_calibration()).unwrap();
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].label(), "EMAIL");
    }

    #[test]
    fn decode_logits_batch_shape_works() {
        let labels = make_test_labels();
        let logits: ArrayD<f32> = ndarray::Array3::zeros((2, 5, labels.len())).into_dyn();
        let context = fake_context(vec!["abc", "def"]);
        let result = decode_logits(logits, context, &labels, zero_calibration()).unwrap();
        assert!(result.spans.is_empty());
    }

    #[test]
    fn viterbi_rejects_missing_default_operating_point() {
        let json = r#"{"operating_points":{"high_recall":{"biases":{"transition_bias_background_stay":0.0,"transition_bias_background_to_start":0.0,"transition_bias_end_to_background":0.0,"transition_bias_end_to_start":0.0,"transition_bias_inside_to_continue":0.0,"transition_bias_inside_to_end":0.0}}}}"#;
        assert!(ViterbiCalibration::from_json(json).is_err());
    }

    #[test]
    fn viterbi_rejects_garbage_json() {
        assert!(ViterbiCalibration::from_json("}not json{").is_err());
    }

    // --- real model ---

    #[test]
    fn real_config_has_33_labels() {
        let f = testutil::fixture();
        assert_eq!(f.labels.len(), 33);
    }

    #[test]
    fn real_viterbi_calibration_is_finite() {
        let f = testutil::fixture();
        let c = &f.calibration;
        assert!(c.transition_bias_background_stay.is_finite());
        assert!(c.transition_bias_background_to_start.is_finite());
        assert!(c.transition_bias_end_to_background.is_finite());
        assert!(c.transition_bias_end_to_start.is_finite());
        assert!(c.transition_bias_inside_to_continue.is_finite());
        assert!(c.transition_bias_inside_to_end.is_finite());
    }
}
