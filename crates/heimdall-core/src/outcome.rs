use std::process::ExitStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildOutcome {
    /// Child exited normally with a status code.
    Exited(i32),
    /// Child terminated because of a Unix signal.
    #[cfg(unix)]
    Signaled(i32),
}

impl ChildOutcome {
    /// Convert this outcome to the process exit code returned by the sandbox.
    #[must_use]
    pub(crate) const fn exit_code(self) -> i32 {
        match self {
            Self::Exited(code) => code,
            #[cfg(unix)]
            Self::Signaled(signal) => 128 + signal,
        }
    }
}

pub(crate) fn child_outcome(status: ExitStatus) -> ChildOutcome {
    if let Some(code) = status.code() {
        ChildOutcome::Exited(code)
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;

            ChildOutcome::Signaled(status.signal().unwrap_or_default())
        }
        #[cfg(not(unix))]
        {
            ChildOutcome::Exited(SANDBOX_MISCONFIGURATION_EXIT_CODE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_child_exit_status_is_returned() {
        let status = ChildOutcome::Exited(17).exit_code();

        assert_eq!(status, 17);
    }

    #[cfg(unix)]
    #[test]
    fn signal_child_exit_status_uses_unix_convention() {
        let status = ChildOutcome::Signaled(15).exit_code();

        assert_eq!(status, 143);
    }
}
