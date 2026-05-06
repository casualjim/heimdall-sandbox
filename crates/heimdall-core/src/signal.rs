use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;

use crate::{Error, Result};

pub(crate) struct SignalForwarding {
    child_pid: Arc<AtomicI32>,
    target_process_group: bool,
    pending_signal: Arc<AtomicI32>,
    handle: signal_hook::iterator::Handle,
    thread: Option<thread::JoinHandle<()>>,
}

impl SignalForwarding {
    pub(crate) fn install() -> Result<Self> {
        Self::install_with_target(false)
    }

    pub(crate) fn install_for_process_group() -> Result<Self> {
        Self::install_with_target(true)
    }

    fn install_with_target(target_process_group: bool) -> Result<Self> {
        let mut signals = signal_hook::iterator::Signals::new([
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
        ])
        .map_err(Error::Hardening)?;
        let handle = signals.handle();
        let child_pid = Arc::new(AtomicI32::new(0));
        let pending_signal = Arc::new(AtomicI32::new(0));
        let thread_child_pid = Arc::clone(&child_pid);
        let thread_pending_signal = Arc::clone(&pending_signal);
        let thread = thread::spawn(move || {
            for signal in signals.forever() {
                let pid = thread_child_pid.load(Ordering::SeqCst);
                if pid > 0 {
                    forward_signal(pid, signal, target_process_group);
                } else {
                    thread_pending_signal.store(signal, Ordering::SeqCst);
                }
            }
        });

        Ok(Self {
            child_pid,
            target_process_group,
            pending_signal,
            handle,
            thread: Some(thread),
        })
    }

    pub(crate) fn set_child(&self, child_id: u32) {
        let pid = child_id as i32;
        self.child_pid.store(pid, Ordering::SeqCst);
        let pending = self.pending_signal.swap(0, Ordering::SeqCst);
        if pending > 0 {
            forward_signal(pid, pending, self.target_process_group);
        }
    }

    fn stop(&mut self) {
        self.child_pid.store(0, Ordering::SeqCst);
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn forward_signal(pid: i32, signal: i32, target_process_group: bool) {
    let target = if target_process_group { -pid } else { pid };
    // SAFETY: `target` is captured from the successfully spawned child process and `signal`
    // comes from the signal-hook iterator for installed signals.
    unsafe {
        libc::kill(target, signal);
    }
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
            if forwarding.pending_signal.load(Ordering::SeqCst) == libc::SIGTERM {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        forwarding.set_child(child.id());
        let status = child.wait().expect("child exits");
        drop(forwarding);
        let marker_contents = std::fs::read_to_string(&marker).expect("marker is written");
        std::fs::remove_dir_all(dir).expect("temp dir is removed");

        assert!(status.success());
        assert_eq!(marker_contents, "replayed");
    }
}
