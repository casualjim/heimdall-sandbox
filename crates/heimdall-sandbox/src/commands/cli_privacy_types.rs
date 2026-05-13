//! Shared CLI-facing type mirrors for privacy-filter domain types.

use heimdall_privacy_filter::{PrivacyExecutionProvider, PrivacyFilterVariant};

/// CLI-facing variant mirror for [`PrivacyFilterVariant`].
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CliPrivacyVariant {
    /// Q4 quantized model (default).
    Q4,
    /// Q4F16 quantized model.
    Q4F16,
    /// Quantized model.
    Quantized,
    /// FP16 model.
    Fp16,
    /// Full precision model.
    Full,
}

impl From<CliPrivacyVariant> for PrivacyFilterVariant {
    fn from(variant: CliPrivacyVariant) -> Self {
        match variant {
            CliPrivacyVariant::Q4 => Self::Q4,
            CliPrivacyVariant::Q4F16 => Self::Q4F16,
            CliPrivacyVariant::Quantized => Self::Quantized,
            CliPrivacyVariant::Fp16 => Self::Fp16,
            CliPrivacyVariant::Full => Self::Full,
        }
    }
}

/// CLI-facing execution provider mirror for [`PrivacyExecutionProvider`].
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CliExecutionProvider {
    /// CPU execution provider (default).
    Cpu,
    /// WebGPU execution provider.
    WebGpu,
}

impl From<CliExecutionProvider> for PrivacyExecutionProvider {
    fn from(provider: CliExecutionProvider) -> Self {
        match provider {
            CliExecutionProvider::Cpu => Self::Cpu,
            CliExecutionProvider::WebGpu => Self::WebGpu,
        }
    }
}
