//! Hugging Face model asset download and cache-only lookup.

use std::path::{Path, PathBuf};

use hf_hub::api::sync::{Api, ApiBuilder};
use hf_hub::{Cache, Repo, RepoType};

use crate::{Error, Result};

/// A pinned revision of a Hugging Face model repository plus an optional cache override.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelSource {
    repository: String,
    revision: String,
    cache_dir: Option<PathBuf>,
}

impl ModelSource {
    /// Create a source for `repository` at `revision`.
    ///
    /// `cache_dir` overrides the Hugging Face cache root; `None` uses the
    /// environment defaults (`HF_HOME`, `HF_ENDPOINT`, ...).
    #[must_use]
    pub fn new(
        repository: impl Into<String>,
        revision: impl Into<String>,
        cache_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            repository: repository.into(),
            revision: revision.into(),
            cache_dir,
        }
    }

    /// Hugging Face model repository, for example `openai/privacy-filter`.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Pinned model revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Download `files` into the cache, or verify them if already present.
    ///
    /// `force` redownloads files that already exist. The first file decides the
    /// snapshot root, so list a file at a known path first.
    pub fn download(&self, files: &[&str], force: bool) -> Result<ModelSnapshot> {
        let first = first_file(files)?;
        let repo = self.api()?.repo(self.repo());
        let mut paths = Vec::with_capacity(files.len());
        for file in files {
            let path = if force {
                repo.download(file)
            } else {
                repo.get(file)
            }
            .map_err(|error| Error::Setup {
                message: format!("failed to download {file}: {error}"),
            })?;
            paths.push(path);
        }
        ModelSnapshot::from_files(paths, first).ok_or_else(|| Error::Setup {
            message: format!("failed to derive snapshot root from {first}"),
        })
    }

    /// Resolve `files` from the local cache only; never downloads.
    ///
    /// Fails with [`Error::NotReady`] naming the first missing file.
    pub fn cached(&self, files: &[&str]) -> Result<ModelSnapshot> {
        let first = first_file(files)?;
        let repo = self.cache().repo(self.repo());
        let mut paths = Vec::with_capacity(files.len());
        for file in files {
            paths.push(repo.get(file).ok_or_else(|| self.not_ready(file))?);
        }
        ModelSnapshot::from_files(paths, first).ok_or_else(|| self.not_ready(first))
    }

    fn repo(&self) -> Repo {
        Repo::with_revision(
            self.repository.clone(),
            RepoType::Model,
            self.revision.clone(),
        )
    }

    fn cache(&self) -> Cache {
        match &self.cache_dir {
            Some(cache_dir) => Cache::new(cache_dir.clone()),
            None => Cache::from_env(),
        }
    }

    fn api(&self) -> Result<Api> {
        let mut builder = ApiBuilder::from_env().with_progress(true);
        if let Some(cache_dir) = &self.cache_dir {
            builder = builder.with_cache_dir(cache_dir.clone());
        }
        builder.build().map_err(|error| Error::Setup {
            message: format!("failed to initialize Hugging Face API: {error}"),
        })
    }

    fn not_ready(&self, asset: &str) -> Error {
        Error::NotReady {
            asset: asset.to_string(),
            repository: self.repository.clone(),
            revision: self.revision.clone(),
        }
    }
}

fn first_file<'a>(files: &[&'a str]) -> Result<&'a str> {
    files.first().copied().ok_or_else(|| Error::InvalidInput {
        detail: "no model files were requested".to_string(),
    })
}

/// Local paths of resolved model files inside one Hugging Face snapshot directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelSnapshot {
    root: PathBuf,
    files: Vec<PathBuf>,
}

impl ModelSnapshot {
    /// Build a snapshot from resolved paths; `first_relative` is the repository-relative
    /// name of `files[0]`, used to find the snapshot root.
    fn from_files(files: Vec<PathBuf>, first_relative: &str) -> Option<Self> {
        let mut root = files.first()?.clone();
        for _ in Path::new(first_relative).components() {
            root.pop();
        }
        if root.as_os_str().is_empty() {
            return None;
        }
        Some(Self { root, files })
    }

    /// Snapshot directory containing the model files at their repository-relative paths.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolved files, in the order they were requested.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_root_strips_nested_relative_path() {
        let snapshot = ModelSnapshot::from_files(
            vec![PathBuf::from("/cache/snapshots/abc/onnx/model.onnx")],
            "onnx/model.onnx",
        )
        .unwrap();
        assert_eq!(snapshot.root(), Path::new("/cache/snapshots/abc"));
    }

    #[test]
    fn snapshot_root_rejects_path_shorter_than_relative_name() {
        assert!(
            ModelSnapshot::from_files(vec![PathBuf::from("model.onnx")], "onnx/model.onnx")
                .is_none()
        );
    }

    #[test]
    fn empty_file_list_is_rejected() {
        let source = ModelSource::new("owner/model", "rev", None);
        assert!(source.cached(&[]).is_err());
        assert!(source.download(&[], false).is_err());
    }
}
