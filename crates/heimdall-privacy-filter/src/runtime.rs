use heimdall_model_runtime::session::OnnxSession;
use tokenizers::Tokenizer;

use crate::input::{EncodedPrivacyInput, PrivacyTextInput};
use crate::model::{
    ModelAssetPaths, PrivacyFilterConfig, usable_token_limit_from_tokenizer_config_json,
};
use crate::output::{
    PrivacyLabels, PrivacySpanOutput, ViterbiCalibration, decode_logits, merge_detected_spans,
};
use crate::{Error, Result};

const LOGITS_OUTPUT: &str = "logits";
const REQUIRED_INPUTS: [&str; 2] = ["attention_mask", "input_ids"];

/// Cache-backed privacy-filter runtime used by redaction commands/tool integrations.
pub struct PrivacyFilterRuntime {
    tokenizer: Tokenizer,
    labels: PrivacyLabels,
    calibration: ViterbiCalibration,
    session: OnnxSession,
    logits_output: String,
    usable_token_limit: usize,
}

impl PrivacyFilterRuntime {
    /// Load the privacy-filter runtime from the local Hugging Face cache only.
    pub fn load(config: PrivacyFilterConfig) -> Result<Self> {
        if !config.is_enabled() {
            return Err(Error::Disabled);
        }

        let snapshot = config
            .model_source()
            .cached(&config.variant().required_files())?;
        let assets = ModelAssetPaths::from_snapshot(snapshot.root(), config.variant());
        let config_json = std::fs::read_to_string(&assets.config)?;
        let labels = PrivacyLabels::from_config_json(&config_json)?;
        let calibration =
            ViterbiCalibration::from_json(&std::fs::read_to_string(&assets.viterbi)?)?;
        let tokenizer = Tokenizer::from_file(&assets.tokenizer)?;
        let usable_token_limit = usable_token_limit_from_tokenizer_config_json(
            &std::fs::read_to_string(&assets.tokenizer_config)?,
        )?;
        let session = OnnxSession::load(&assets.onnx, config.execution_provider())?;
        session.require_inputs(&REQUIRED_INPUTS)?;
        let logits_output = logits_output_name(&session)?;

        Ok(Self {
            tokenizer,
            labels,
            calibration,
            session,
            logits_output,
            usable_token_limit,
        })
    }

    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    pub const fn set_usable_token_limit_for_test(&mut self, limit: usize) {
        self.usable_token_limit = limit;
    }

    /// Detect sensitive spans in one text input.
    pub fn detect_spans(&mut self, text: &str) -> Result<PrivacySpanOutput> {
        self.detect_batch(PrivacyTextInput::single(text.to_owned())?)
    }

    /// Detect sensitive spans in one or more text inputs.
    pub fn detect_batch(&mut self, input: PrivacyTextInput) -> Result<PrivacySpanOutput> {
        let encoded = EncodedPrivacyInput::encode(
            input,
            &self.tokenizer,
            self.labels.pad_token_id(),
            self.usable_token_limit,
        )?;
        let context = encoded.context.clone();
        let logits = self.session.run(
            &encoded.input_ids,
            &encoded.attention_mask,
            &self.logits_output,
        )?;
        let mut output = decode_logits(logits, context, &self.labels, self.calibration)?;
        output.spans = merge_detected_spans(output.spans);
        Ok(output)
    }
}

/// Pick `logits`, or the model's only output when it is not named `logits`.
fn logits_output_name(session: &OnnxSession) -> Result<String> {
    let outputs = session.output_names();
    match outputs.as_slice() {
        _ if outputs.contains(&LOGITS_OUTPUT) => Ok(LOGITS_OUTPUT.to_string()),
        [only] => Ok((*only).to_string()),
        _ => Err(Error::Schema {
            detail: format!(
                "expected output `logits` or a single output tensor, found {outputs:?}"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn load_rejects_disabled_config() {
        assert!(PrivacyFilterRuntime::load(PrivacyFilterConfig::disabled()).is_err());
    }

    #[test]
    fn load_succeeds_with_real_model() {
        let f = testutil::fixture();
        PrivacyFilterRuntime::load(f.config.clone()).unwrap();
    }

    #[test]
    fn detect_spans_finds_email() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let output = runtime.detect_spans("alice@example.com").unwrap();
        assert!(!output.spans.is_empty());
        assert!(output.spans.iter().any(|s| s.label().contains("email")));
    }

    #[test]
    fn detect_batch_two_windows() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let input = PrivacyTextInput::new(vec![
            "alice@example.com".to_string(),
            "415-555-1234".to_string(),
        ])
        .unwrap();
        let output = runtime.detect_batch(input).unwrap();
        assert!(!output.spans.is_empty());
    }

    #[test]
    fn detect_spans_plain_text_does_not_error() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let _ = runtime.detect_spans("just some words").unwrap();
    }

    #[test]
    fn detect_spans_finds_email_after_first_window() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        runtime.set_usable_token_limit_for_test(32);
        let text = format!("{} alice@example.com", "filler ".repeat(80));
        let output = runtime.detect_spans(&text).unwrap();
        assert!(
            output
                .spans
                .iter()
                .any(|span| span.label().contains("email") && span.start() > 100),
            "expected email after first window, got {:?}",
            output.spans
        );
    }
}
