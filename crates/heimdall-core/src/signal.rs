use std::sync::{Arc, Mutex};
use std::thread;

use crate::{Error, Result};

pub(crate) struct SignalForwarding {
    state: Arc<Mutex<SignalState>>,
    target: SignalTarget,
    handle: signal_hook::iterator::Handle,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Clone, Copy)]
enum SignalTarget {
    Child,
    ProcessGroup,
    #[cfg(target_os = "linux")]
    BubblewrapPayload,
}

#[derive(Default)]
struct SignalState {
    child_pid: Option<i32>,
    pending_signals: Vec<i32>,
    // Asynchronous forwarding happens after the child is already running; store failures only as
    // non-fatal diagnostics because there is no safe way to return them to the waiting caller.
    last_forward_error: Option<std::io::ErrorKind>,
}

impl SignalForwarding {
    pub(crate) fn install() -> Result<Self> {
        Self::install_with_target(SignalTarget::Child)
    }

    pub(crate) fn install_for_process_group() -> Result<Self> {
        Self::install_with_target(SignalTarget::ProcessGroup)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn install_for_bubblewrap_payload() -> Result<Self> {
        Self::install_with_target(SignalTarget::BubblewrapPayload)
    }

    fn install_with_target(target: SignalTarget) -> Result<Self> {
        let mut signals = signal_hook::iterator::Signals::new([
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
        ])
        .map_err(Error::Hardening)?;
        let handle = signals.handle();
        let state = Arc::new(Mutex::new(SignalState::default()));
        let thread_state = Arc::clone(&state);
        let thread = thread::spawn(move || {
            for signal in signals.forever() {
                let child_pid = {
                    let mut state = thread_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Some(pid) = state.child_pid {
                        pid
                    } else {
                        state.pending_signals.push(signal);
                        continue;
                    }
                };
                if let Err(error) = forward_signal(child_pid, signal, target) {
                    let mut state = thread_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.last_forward_error = Some(error.kind());
                }
            }
        });

        Ok(Self {
            state,
            target,
            handle,
            thread: Some(thread),
        })
    }

    pub(crate) fn set_child(&self, child_id: u32) -> Result<()> {
        let pid = child_id as i32;
        let pending = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.child_pid = Some(pid);
            std::mem::take(&mut state.pending_signals)
        };
        for signal in pending {
            forward_signal(pid, signal, self.target).map_err(Error::Hardening)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn pending_signal_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_signals
            .len()
    }

    fn stop(&mut self) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.child_pid = None;
            let _last_forward_error = state.last_forward_error.take();
        }
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn forward_signal(pid: i32, signal: i32, target: SignalTarget) -> std::io::Result<()> {
    match target {
        SignalTarget::Child => kill_pid(pid, signal),
        SignalTarget::ProcessGroup => kill_pid(-pid, signal),
        #[cfg(target_os = "linux")]
        SignalTarget::BubblewrapPayload => forward_signal_to_bubblewrap_payload(pid, signal),
    }
}

fn kill_pid(pid: i32, signal: i32) -> std::io::Result<()> {
    // SAFETY: `pid` is captured from the successfully spawned child process and `signal`
    // comes from the signal-hook iterator for installed signals.
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn forward_signal_to_bubblewrap_payload(bubblewrap_pid: i32, signal: i32) -> std::io::Result<()> {
    let mut descendants = Vec::new();
    append_descendants(bubblewrap_pid, &mut descendants)?;
    if descendants.is_empty() {
        return kill_pid(bubblewrap_pid, signal);
    }
    for pid in descendants {
        kill_pid(pid, signal)?;
    }
    if signal == libc::SIGQUIT {
        kill_pid(bubblewrap_pid, signal)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn append_descendants(pid: i32, descendants: &mut Vec<i32>) -> std::io::Result<()> {
    for child in child_pids(pid)? {
        descendants.push(child);
        append_descendants(child, descendants)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn child_pids(pid: i32) -> std::io::Result<Vec<i32>> {
    let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))?;
    children
        .split_whitespace()
        .map(|child| {
            child.parse::<i32>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid child pid {child}: {error}"),
                )
            })
        })
        .collect()
}

impl Drop for SignalForwarding {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn pending_signal_is_replayed_when_child_is_registered() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after Unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("heimdall-pending-signal-{stamp}"));
        std::fs::create_dir(&dir).expect("temp dir is created");
        let marker = dir.join("marker");
        let ready = dir.join("ready");
        let script = format!(
            "trap 'printf replayed > {}; exit 0' TERM; touch {}; while true; do sleep 1; done",
            marker.display(),
            ready.display()
        );
        let mut child = Command::new("sh")
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child starts");
        for _ in 0..40 {
            if ready.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ready.exists(), "child did not signal readiness");

        let forwarding = SignalForwarding::install().expect("signal forwarding installs");
        // SAFETY: Sends an installed signal to this process so forwarding records it before a
        // child pid is registered.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGTERM);
        }
        for _ in 0..40 {
            if forwarding.pending_signal_count() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        forwarding
            .set_child(child.id())
            .expect("child signal target registers");
        let status = child.wait().expect("child exits");
        drop(forwarding);
        let marker_contents = std::fs::read_to_string(&marker).expect("marker is written");
        std::fs::remove_dir_all(dir).expect("temp dir is removed");

        assert!(status.success());
        assert_eq!(marker_contents, "replayed");
    }
}
