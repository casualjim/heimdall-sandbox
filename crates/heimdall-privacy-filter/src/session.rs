use ndarray::ArrayD;
use ort::execution_providers::{CPUExecutionProvider, WebGPUExecutionProvider};
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::TensorRef;

use crate::input::EncodedPrivacyInput;
use crate::model::{PrivacyExecutionProvider, PrivacyFilterConfig};
use crate::{Error, Result};

/// Owned logits tensor returned from ONNX Runtime.
pub type LogitsTensor = ArrayD<f32>;

/// ONNX inference thread pool size.
const ONNX_INTRA_THREADS: usize = 4;

fn onnx_error(error: impl std::fmt::Display) -> Error {
    Error::Onnx(error.to_string())
}

/// Thin direct wrapper around an ONNX Runtime session for OpenAI privacy-filter.
pub struct PrivacyOnnxSession {
    session: Session,
}

impl PrivacyOnnxSession {
    /// Load a privacy-filter ONNX session from a local file and check its schema.
    pub fn load(
        model_path: impl AsRef<std::path::Path>,
        config: &PrivacyFilterConfig,
    ) -> Result<Self> {
        let builder = Session::builder().map_err(onnx_error)?;
        let builder = builder
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(onnx_error)?;
        let builder = builder
            .with_intra_threads(ONNX_INTRA_THREADS)
            .map_err(onnx_error)?;

        let mut builder = match config.execution_provider() {
            PrivacyExecutionProvider::Cpu => builder
                .with_execution_providers([CPUExecutionProvider::default().build()])
                .map_err(onnx_error)?,
            PrivacyExecutionProvider::WebGpu => builder
                .with_execution_providers([WebGPUExecutionProvider::default().build()])
                .map_err(onnx_error)?,
        };

        let session = builder.commit_from_file(model_path).map_err(onnx_error)?;
        let this = Self { session };
        this.validate_schema()?;
        Ok(this)
    }

    /// Validate model input/output names before inference.
    pub fn validate_schema(&self) -> Result<()> {
        let inputs = self
            .session
            .inputs()
            .iter()
            .map(|input| input.name())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_inputs = ["attention_mask", "input_ids"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if inputs != expected_inputs {
            return Err(Error::Schema {
                detail: format!("expected inputs {expected_inputs:?}, found {inputs:?}"),
            });
        }

        let outputs = self
            .session
            .outputs()
            .iter()
            .map(|output| output.name())
            .collect::<std::collections::BTreeSet<_>>();
        if !outputs.contains("logits") && outputs.len() != 1 {
            return Err(Error::Schema {
                detail: format!(
                    "expected output `logits` or a single output tensor, found {outputs:?}"
                ),
            });
        }
        Ok(())
    }

    /// Run inference and return owned logits.
    pub fn run(&mut self, input: &EncodedPrivacyInput) -> Result<LogitsTensor> {
        let input_ids = TensorRef::from_array_view(&input.input_ids).map_err(onnx_error)?;
        let attention_mask =
            TensorRef::from_array_view(&input.attention_mask).map_err(onnx_error)?;
        let outputs = self
            .session
            .run(ort::inputs![
                "input_ids" => input_ids,
                "attention_mask" => attention_mask,
            ])
            .map_err(onnx_error)?;

        let logits = outputs.get("logits").map(|value| {
            value
                .try_extract_array::<f32>()
                .map_err(onnx_error)
                .map(|array| array.to_owned())
        });

        let array = match logits {
            Some(Ok(array)) => array,
            Some(Err(error)) => return Err(error),
            None if outputs.len() == 1 => outputs
                .iter()
                .next()
                .ok_or_else(|| Error::Decode {
                    detail: "model returned no outputs".to_string(),
                })?
                .1
                .try_extract_array::<f32>()
                .map_err(onnx_error)?
                .to_owned(),
            None => {
                return Err(Error::Decode {
                    detail: "model returned no logits output".to_string(),
                });
            }
        };
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn real_model_loads_and_passes_schema() {
        let f = testutil::fixture();
        let session = PrivacyOnnxSession::load(&f.assets.onnx, &f.config).unwrap();
        session.validate_schema().unwrap();
    }
}
