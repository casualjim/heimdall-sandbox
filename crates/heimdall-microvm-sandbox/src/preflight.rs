use crate::{Error, Result};

pub(crate) fn preflight_host() -> Result<()> {
    preflight_supported_host()?;
    microsandbox::config::resolve_msb_path().map_err(Error::from)?;
    microsandbox::config::resolve_libkrunfw_path().map_err(Error::from)?;
    preflight_kvm()?;
    Ok(())
}

fn preflight_supported_host() -> Result<()> {
    if cfg!(target_os = "linux") && (cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64"))
    {
        return Ok(());
    }
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        return Ok(());
    }
    Err(Error::platform(
        "microvm runtime supports linux KVM and aarch64-apple-darwin only",
    ))
}

#[cfg(target_os = "linux")]
fn preflight_kvm() -> Result<()> {
    let kvm = Path::new("/dev/kvm");
    if kvm.is_file() || kvm.exists() {
        Ok(())
    } else {
        Err(Error::platform("microvm runtime requires /dev/kvm"))
    }
}

#[cfg(not(target_os = "linux"))]
fn preflight_kvm() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_support_matches_target_matrix() {
        let result = preflight_supported_host();
        let supported_target = (cfg!(target_os = "linux")
            && (cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64")))
            || (cfg!(target_os = "macos") && cfg!(target_arch = "aarch64"));
        assert_eq!(result.is_ok(), supported_target);
    }
}
