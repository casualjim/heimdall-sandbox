//! Device/socket access diagnostics for bind-mounted sandbox targets.
//!
//! Bubblewrap `--unshare-user` drops the caller's supplementary groups inside the user
//! namespace. A bind mount preserves the host inode (and its xattrs), so uid-based access
//! survives but group-based access (e.g. `root:kvm` 0660 for `/dev/kvm`, `root:docker` 0660
//! for `/var/run/docker.sock`) does not. When a target's only path to read/write is a
//! supplementary group, emit the exact `setfacl` remediation: a uid POSIX-ACL entry survives
//! the bind mount and does not depend on groups.
//!
//! Device nodes also need `--dev-bind` (not `--bind`) so the mount is not `nodev`; the
//! planner handles that separately. This module only covers the DAC/group dimension.
//!
//! Detection is best-effort: it never blocks mounting and silently skips targets it cannot
//! classify. The mount itself still happens; only a diagnostic is emitted.

use std::ffi::CString;
use std::fmt;
use std::fs::{self, FileType};
use std::path::{Path, PathBuf};

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

/// Kind of bind target that the sandbox user may be unable to access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Character device node, e.g. `/dev/kvm`.
    CharDevice,
    /// Block device node.
    BlockDevice,
    /// UNIX domain socket, e.g. `/var/run/docker.sock`.
    Socket,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CharDevice => f.write_str("char device"),
            Self::BlockDevice => f.write_str("block device"),
            Self::Socket => f.write_str("socket"),
        }
    }
}

/// A bind-mounted target the sandbox user will not be able to read/write.
#[derive(Debug, Clone)]
pub struct DeviceAccessWarning {
    path: PathBuf,
    kind: NodeKind,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
}

impl fmt::Display for DeviceAccessWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "heimdall: {} ({}) is bind-mounted into the sandbox but the sandbox user will not be able to read/write it.",
            self.path.display(),
            self.kind
        )?;
        writeln!(
            f,
            "  node: owner uid {} gid {}, mode {:04o}",
            self.owner_uid,
            self.owner_gid,
            self.mode & 0o7777
        )?;
        writeln!(
            f,
            "  reason: supplementary groups are dropped inside the user namespace, so group-based access (e.g. kvm/docker) does not survive the bind mount; a uid POSIX-ACL entry does."
        )?;
        write!(
            f,
            "  fix:   sudo setfacl -m u:$USER:rw {}",
            self.path.display()
        )
    }
}

/// Classify a filesystem node as a bind target of interest.
///
/// Returns `None` for regular files, directories, symlinks, fifos, and unknown types so the
/// caller only runs access checks on device nodes and sockets.
#[must_use]
pub fn classify_node(file_type: &FileType) -> Option<NodeKind> {
    if file_type.is_char_device() {
        Some(NodeKind::CharDevice)
    } else if file_type.is_block_device() {
        Some(NodeKind::BlockDevice)
    } else if file_type.is_socket() {
        Some(NodeKind::Socket)
    } else {
        None
    }
}

/// POSIX ACL entry as parsed from the `system.posix_acl_access` xattr blob.
#[derive(Debug, Clone, Copy)]
struct AclEntry {
    tag: u16,
    perm: u16,
    id: u32,
}

const ACL_USER: u16 = 0x02;
const ACL_MASK: u16 = 0x10;

/// Parse the `system.posix_acl_access` xattr blob into ACL entries.
///
/// Layout: a little-endian `u32` version header followed by 8-byte entries
/// (`u16` tag, `u16` perm, `u32` id). Malformed or truncated buffers yield an empty vec.
#[must_use]
fn parse_acl_entries(buf: &[u8]) -> Vec<AclEntry> {
    const HEADER: usize = 4;
    const ENTRY: usize = 8;
    if buf.len() < HEADER {
        return Vec::new();
    }
    let mut entries = Vec::new();
    let mut cursor = HEADER;
    while cursor + ENTRY <= buf.len() {
        let tag = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        let perm = u16::from_le_bytes([buf[cursor + 2], buf[cursor + 3]]);
        let id = u32::from_le_bytes([
            buf[cursor + 4],
            buf[cursor + 5],
            buf[cursor + 6],
            buf[cursor + 7],
        ]);
        entries.push(AclEntry { tag, perm, id });
        cursor += ENTRY;
    }
    entries
}

/// Decide whether `uid` gets read+write access to a node, assuming supplementary groups are
/// unavailable (the sandbox reality).
///
/// Pure and filesystem-free so it is unit-testable. `acl` is the raw
/// `system.posix_acl_access` xattr blob when present.
///
/// # Rules
///
/// - Owner match grants via the file mode's user bits.
/// - World (`other`) bits grant regardless of identity.
/// - An `ACL_USER` entry for `uid`, masked by `ACL_MASK` when present, grants.
/// - Group-based grants (mode group bits, `ACL_GROUP_OBJ`, `ACL_GROUP`) never grant here
///   because the user namespace drops supplementary groups.
#[must_use]
pub fn uid_has_rw_access(mode: u32, owner_uid: u32, acl: Option<&[u8]>, uid: u32) -> bool {
    const RW: u16 = 0o6;
    if owner_uid == uid {
        return ((mode >> 6) & u32::from(RW)) == u32::from(RW);
    }
    if (mode & u32::from(RW)) == u32::from(RW) {
        return true;
    }
    if let Some(buf) = acl {
        let entries = parse_acl_entries(buf);
        let mask = entries
            .iter()
            .find(|entry| entry.tag == ACL_MASK)
            .map(|entry| entry.perm);
        for entry in entries
            .iter()
            .filter(|entry| entry.tag == ACL_USER && entry.id == uid)
        {
            let perm = match mask {
                Some(mask) => entry.perm & mask,
                None => entry.perm,
            };
            if perm & RW == RW {
                return true;
            }
        }
    }
    false
}

/// Read the `system.posix_acl_access` xattr without following symlinks.
///
/// Returns `None` when the filesystem lacks ACL support or no ACL is set; growth-retries on
/// `ERANGE`. All other failures are treated as "no ACL" so diagnostics fail open.
fn read_acl_access(path: &Path) -> Option<Vec<u8>> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = b"system.posix_acl_access\0";
    let mut buffer = vec![0_u8; 256];
    loop {
        let written = unsafe {
            libc::lgetxattr(
                cpath.as_ptr(),
                name.as_ptr().cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if written >= 0 {
            buffer.truncate(written as usize);
            return Some(buffer);
        }
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::ERANGE {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        return None;
    }
}

/// Collect access warnings for the given bind target paths.
///
/// Flags device nodes and sockets whose read/write access depends on a supplementary group
/// the user namespace drops. Best-effort: paths that cannot be stat'd or classified are
/// skipped. Never blocks mounting.
#[must_use]
pub fn collect_device_access_warnings(paths: &[PathBuf]) -> Vec<DeviceAccessWarning> {
    let uid = unsafe { libc::getuid() };
    let mut warnings = Vec::new();
    for path in paths {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        let Some(kind) = classify_node(&metadata.file_type()) else {
            continue;
        };
        let mode = metadata.mode();
        let owner_uid = metadata.uid();
        let owner_gid = metadata.gid();
        let acl = read_acl_access(path);
        if uid_has_rw_access(mode, owner_uid, acl.as_deref(), uid) {
            continue;
        }
        warnings.push(DeviceAccessWarning {
            path: path.clone(),
            kind,
            owner_uid,
            owner_gid,
            mode,
        });
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_OTHER: u16 = 0x20;

    fn acl_entry(tag: u16, perm: u16, id: u32) -> [u8; 8] {
        let mut entry = [0_u8; 8];
        entry[0..2].copy_from_slice(&tag.to_le_bytes());
        entry[2..4].copy_from_slice(&perm.to_le_bytes());
        entry[4..8].copy_from_slice(&id.to_le_bytes());
        entry
    }

    fn acl_blob(entries: &[[u8; 8]]) -> Vec<u8> {
        let mut blob = 0x0002_u32.to_le_bytes().to_vec();
        for entry in entries {
            blob.extend_from_slice(entry);
        }
        blob
    }

    #[test]
    fn owner_user_bits_grant_without_group_or_acl() {
        assert!(uid_has_rw_access(0o660, 1000, None, 1000));
    }

    #[test]
    fn other_bits_grant_without_owner_match() {
        assert!(uid_has_rw_access(0o006, 0, None, 1000));
    }

    #[test]
    fn group_bits_alone_do_not_grant() {
        assert!(!uid_has_rw_access(0o660, 0, None, 1000));
    }

    #[test]
    fn user_acl_entry_grants_when_mask_allows() {
        let blob = acl_blob(&[
            acl_entry(ACL_USER_OBJ, 0o6, 0),
            acl_entry(ACL_USER, 0o6, 1000),
            acl_entry(ACL_GROUP_OBJ, 0o6, 0),
            acl_entry(ACL_MASK, 0o6, 0),
            acl_entry(ACL_OTHER, 0o0, 0),
        ]);
        assert!(uid_has_rw_access(0o660, 0, Some(&blob), 1000));
    }

    #[test]
    fn user_acl_entry_denied_when_mask_blocks_write() {
        let blob = acl_blob(&[
            acl_entry(ACL_USER_OBJ, 0o6, 0),
            acl_entry(ACL_USER, 0o6, 1000),
            acl_entry(ACL_GROUP_OBJ, 0o6, 0),
            acl_entry(ACL_MASK, 0o4, 0),
            acl_entry(ACL_OTHER, 0o0, 0),
        ]);
        assert!(!uid_has_rw_access(0o660, 0, Some(&blob), 1000));
    }

    #[test]
    fn user_acl_entry_for_other_uid_does_not_grant() {
        let blob = acl_blob(&[
            acl_entry(ACL_USER_OBJ, 0o6, 0),
            acl_entry(ACL_USER, 0o6, 1001),
            acl_entry(ACL_GROUP_OBJ, 0o6, 0),
            acl_entry(ACL_MASK, 0o6, 0),
            acl_entry(ACL_OTHER, 0o0, 0),
        ]);
        assert!(!uid_has_rw_access(0o660, 0, Some(&blob), 1000));
    }

    #[test]
    fn owner_missing_write_does_not_grant_even_with_group_rw() {
        assert!(!uid_has_rw_access(0o060, 1000, None, 1000));
    }

    #[test]
    fn empty_acl_does_not_grant() {
        assert!(!uid_has_rw_access(0o660, 0, Some(&[]), 1000));
    }

    #[test]
    fn malformed_acl_is_ignored() {
        assert!(!uid_has_rw_access(0o660, 0, Some(&[0x42]), 1000));
    }

    #[test]
    fn classify_node_recognizes_a_real_char_device() {
        let kvm = std::fs::metadata("/dev/null");
        if let Ok(meta) = kvm {
            assert_eq!(classify_node(&meta.file_type()), Some(NodeKind::CharDevice));
        }
    }
}
