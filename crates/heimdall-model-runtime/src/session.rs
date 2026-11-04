//! ONNX Runtime session management for token-classification style models.

use std::collections::BTreeSet;
use std::fmt::Display;
use std::path::Path;

use ndarray::{Array2, ArrayD};
use ort::execution_providers::CPUExecutionProvider;
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
use ort::execution_providers::WebGPUExecutionProvider;
use ort::session::Session;
use ort::session::builder::{GraphOptimizationLevel, SessionBuilder};
use ort::value::TensorRef;
use serde::{Deserialize, Serialize};

use crate::{Error, Result, ensure_ort_initialized};

/// ONNX inference thread pool size.
const ONNX_INTRA_THREADS: usize = 4;

/// ONNX Runtime execution provider selection.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionProvider {
    /// CPU execution provider. This is the default and most portable path.
    #[default]
    Cpu,
    /// WebGPU execution provider. Must be explicitly selected.
    WebGpu,
}

fn onnx_error(error: impl Display) -> Error {
    Error::Onnx(error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn configure_webgpu(builder: SessionBuilder) -> Result<SessionBuilder> {
    builder
        .with_execution_providers([WebGPUExecutionProvider::default().build()])
        .map_err(onnx_error)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn configure_webgpu(builder: SessionBuilder) -> Result<SessionBuilder> {
    let _ = builder;
    Err(Error::Onnx(
        "WebGPU execution provider is unavailable in Linux arm64 builds; use CPU or provide a Linux arm64 ONNX Runtime/Dawn WebGPU build".to_string(),
    ))
}

/// ONNX Runtime session for models taking `input_ids` and `attention_mask`
/// tensors of shape `[batch, tokens]`.
pub struct OnnxSession {
    session: Session,
}

impl OnnxSession {
    /// Load an ONNX model file with the selected execution provider.
    pub fn load(model_path: impl AsRef<Path>, provider: ExecutionProvider) -> Result<Self> {
        ensure_ort_initialized()?;
        let builder = Session::builder()
            .map_err(onnx_error)?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(onnx_error)?
            .with_intra_threads(ONNX_INTRA_THREADS)
            .map_err(onnx_error)?;

        let mut builder = match provider {
            ExecutionProvider::Cpu => builder
                .with_execution_providers([CPUExecutionProvider::default().build()])
                .map_err(onnx_error)?,
            ExecutionProvider::WebGpu => configure_webgpu(builder)?,
        };

        let session = builder.commit_from_file(model_path).map_err(onnx_error)?;
        Ok(Self { session })
    }

    /// Names of the model's input tensors.
    #[must_use]
    pub fn input_names(&self) -> Vec<&str> {
        self.session
            .inputs()
            .iter()
            .map(|input| input.name())
            .collect()
    }

    /// Names of the model's output tensors.
    #[must_use]
    pub fn output_names(&self) -> Vec<&str> {
        self.session
            .outputs()
            .iter()
            .map(|output| output.name())
            .collect()
    }

    /// Fail with [`Error::Schema`] unless the model's inputs are exactly `expected`.
    pub fn require_inputs(&self, expected: &[&str]) -> Result<()> {
        let found = self.input_names().into_iter().collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if found != expected {
            return Err(Error::Schema {
                detail: format!("expected inputs {expected:?}, found {found:?}"),
            });
        }
        Ok(())
    }

    /// Run inference and return the named `f32` output as an owned tensor.
    pub fn run(
        &mut self,
        input_ids: &Array2<i64>,
        attention_mask: &Array2<i64>,
        output: &str,
    ) -> Result<ArrayD<f32>> {
        let input_ids = TensorRef::from_array_view(input_ids).map_err(onnx_error)?;
        let attention_mask = TensorRef::from_array_view(attention_mask).map_err(onnx_error)?;
        let outputs = self
            .session
            .run(ort::inputs![
                "input_ids" => input_ids,
                "attention_mask" => attention_mask,
            ])
            .map_err(onnx_error)?;
        let value = outputs.get(output).ok_or_else(|| Error::Schema {
            detail: format!("model returned no output `{output}`"),
        })?;
        let tensor = value.try_extract_array::<f32>().map_err(onnx_error)?;
        Ok(tensor.to_owned())
    }
}
