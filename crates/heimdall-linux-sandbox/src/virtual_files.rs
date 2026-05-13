use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::policy::{FilesystemPolicy, broadly_grants_cwd};
use crate::{Error, Result};
use heimdall_sandbox_policy::MaterializedFilesystemPolicy;

const SYNTHETIC_PASSWD: &str = "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n";
const SYNTHETIC_GROUP: &str = "nogroup:x:65534:\n";

pub(crate) struct BubblewrapResources {
    virtual_files: VirtualDataFiles,
    scratch_dir: VirtualScratchDir,
    _protected_placeholders: ProtectedPlaceholders,
}

impl BubblewrapResources {
    pub(crate) fn prepare(
        cwd: &Path,
        materialized: &MaterializedFilesystemPolicy,
        filesystem_policy: &FilesystemPolicy,
    ) -> Result<Self> {
        BubblewrapResourcesBuilder::new(cwd, materialized, filesystem_policy).prepare()
    }

    pub(crate) fn virtual_files(&self) -> &[VirtualDataFile] {
        self.virtual_files.as_slice()
    }

    pub(crate) fn empty_file(&self) -> PathBuf {
        self.scratch_dir.path.join("__empty_file")
    }

    pub(crate) fn empty_dir(&self) -> PathBuf {
        self.scratch_dir.path.join("__empty_dir")
    }
}

struct BubblewrapResourcesBuilder<'a> {
    cwd: &'a Path,
    materialized: &'a MaterializedFilesystemPolicy,
    filesystem_policy: &'a FilesystemPolicy,
}

impl<'a> BubblewrapResourcesBuilder<'a> {
    const fn new(
        cwd: &'a Path,
        materialized: &'a MaterializedFilesystemPolicy,
        filesystem_policy: &'a FilesystemPolicy,
    ) -> Self {
        Self {
            cwd,
            materialized,
            filesystem_policy,
        }
    }

    fn prepare(self) -> Result<BubblewrapResources> {
        let protected_placeholders = ProtectedPlaceholders::prepare(
            self.cwd,
            self.materialized.protected_targets(),
            self.filesystem_policy.writable(),
        )?;
        let virtual_files =
            VirtualDataFiles::write(&identity_virtual_files(self.filesystem_policy))?;
        let scratch_dir = VirtualScratchDir::create()?;
        Ok(BubblewrapResources {
            virtual_files,
            scratch_dir,
            _protected_placeholders: protected_placeholders,
        })
    }
}

pub(crate) struct VirtualDataFile {
    pub(crate) sandbox_path: PathBuf,
    file: File,
}

impl VirtualDataFile {
    pub(crate) fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

struct VirtualDataFiles {
    files: Vec<VirtualDataFile>,
}

impl VirtualDataFiles {
    fn write(files: &BTreeMap<PathBuf, String>) -> Result<Self> {
        let files = files
            .iter()
            .enumerate()
            .map(|(index, (sandbox_path, content))| {
                let mut file = create_virtual_file_data(index)?;
                file.write_all(content.as_bytes()).map_err(|error| {
                    Error::sandbox_misconfiguration(format!(
                        "failed to write virtual file: {error}"
                    ))
                })?;
                file.seek(SeekFrom::Start(0)).map_err(|error| {
                    Error::sandbox_misconfiguration(format!(
                        "failed to rewind virtual file: {error}"
                    ))
                })?;
                Ok(VirtualDataFile {
                    sandbox_path: sandbox_path.clone(),
                    file,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { files })
    }

    fn as_slice(&self) -> &[VirtualDataFile] {
        &self.files
    }
}

#[cfg(target_os = "linux")]
fn create_virtual_file_data(index: usize) -> Result<File> {
    let name = CString::new(format!("heimdall-virtual-{index}")).map_err(|error| {
        Error::sandbox_misconfiguration(format!("invalid virtual file name: {error}"))
    })?;
    // SAFETY: `name` is a valid nul-terminated C string and flags are zero so the fd
    // is inherited by the bubblewrap child for `--ro-bind-data`.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(Error::sandbox_misconfiguration(format!(
            "failed to create virtual file data fd: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `fd` is uniquely owned after successful `memfd_create`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn create_virtual_file_data(index: usize) -> Result<File> {
    let path = std::env::temp_dir().join(format!(
        "heimdall-virtual-data-{index}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| Error::sandbox_misconfiguration(format!(
                "system clock error: {error}"
            )))?
            .as_nanos()
    ));
    let file = File::create(&path).map_err(|error| {
        Error::sandbox_misconfiguration(format!("failed to create virtual file data: {error}"))
    })?;
    let _ = std::fs::remove_file(&path);
    Ok(file)
}

struct VirtualScratchDir {
    path: PathBuf,
}

impl VirtualScratchDir {
    fn create() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "heimdall-virtual-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| {
                    Error::sandbox_misconfiguration(format!("system clock error: {error}"))
                })?
                .as_nanos()
        ));
        std::fs::create_dir(&root).map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "failed to create virtual scratch dir: {error}"
            ))
        })?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                Error::sandbox_misconfiguration(format!(
                    "failed to chmod virtual scratch dir: {error}"
                ))
            },
        )?;
        std::fs::create_dir(root.join("__empty_dir")).map_err(|error| {
            Error::sandbox_misconfiguration(format!("failed to create empty virtual dir: {error}"))
        })?;
        File::create(root.join("__empty_file")).map_err(|error| {
            Error::sandbox_misconfiguration(format!("failed to create empty virtual file: {error}"))
        })?;
        Ok(Self { path: root })
    }
}

impl Drop for VirtualScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

enum ProtectedPlaceholder {
    File(PathBuf),
    Directory(PathBuf),
    HeimdallWildcardCleanup {
        cwd: PathBuf,
        existing_paths: BTreeSet<PathBuf>,
    },
}

impl Drop for ProtectedPlaceholder {
    fn drop(&mut self) {
        match self {
            Self::File(path) => {
                let _ = std::fs::remove_file(path);
            }
            Self::Directory(path) => {
                let _ = std::fs::remove_dir(path);
            }
            Self::HeimdallWildcardCleanup {
                cwd,
                existing_paths,
            } => remove_created_heimdall_control_paths(cwd, existing_paths),
        }
    }
}

struct ProtectedPlaceholders {
    _placeholders: Vec<ProtectedPlaceholder>,
}

impl ProtectedPlaceholders {
    fn prepare(
        cwd: &Path,
        paths: &BTreeSet<PathBuf>,
        writable_patterns: &[String],
    ) -> Result<Self> {
        let mut placeholders = Vec::new();
        if broadly_grants_cwd(writable_patterns) {
            placeholders.push(ProtectedPlaceholder::HeimdallWildcardCleanup {
                cwd: cwd.to_path_buf(),
                existing_paths: existing_heimdall_control_paths(cwd)?,
            });
        }
        for path in paths {
            if path.exists() {
                continue;
            }
            if missing_protected_path_is_directory(path) {
                std::fs::create_dir(path).map_err(|error| {
                    Error::sandbox_misconfiguration(format!(
                        "failed to create protected placeholder {}: {error}",
                        path.display()
                    ))
                })?;
                placeholders.push(ProtectedPlaceholder::Directory(path.clone()));
            } else {
                File::create(path).map_err(|error| {
                    Error::sandbox_misconfiguration(format!(
                        "failed to create protected placeholder {}: {error}",
                        path.display()
                    ))
                })?;
                placeholders.push(ProtectedPlaceholder::File(path.clone()));
            }
        }
        Ok(Self {
            _placeholders: placeholders,
        })
    }
}

pub(crate) fn identity_virtual_files(policy: &FilesystemPolicy) -> BTreeMap<PathBuf, String> {
    let mut files = BTreeMap::from([
        (PathBuf::from("/etc/passwd"), SYNTHETIC_PASSWD.to_string()),
        (PathBuf::from("/etc/group"), SYNTHETIC_GROUP.to_string()),
    ]);
    files.extend(policy.virtual_files().clone());
    files
}

fn missing_protected_path_is_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | ".agents" | ".pi"))
}

fn existing_heimdall_control_paths(cwd: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    for entry in std::fs::read_dir(cwd).map_err(|error| {
        Error::sandbox_misconfiguration(format!("failed to read {}: {error}", cwd.display()))
    })? {
        let entry = entry.map_err(|error| {
            Error::sandbox_misconfiguration(format!("failed to read {}: {error}", cwd.display()))
        })?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".heimdall-")
        {
            paths.insert(entry.path());
        }
    }
    Ok(paths)
}

fn remove_created_heimdall_control_paths(cwd: &Path, existing_paths: &BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".heimdall-")
            || existing_paths.contains(&entry.path())
        {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        } else {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
