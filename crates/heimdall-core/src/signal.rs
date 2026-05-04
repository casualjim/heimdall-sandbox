use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;

use crate::{Error, Result};

pub(crate) struct SignalForwarding {
    child_pid: Arc<AtomicI32>,
    handle: signal_hook::iterator::Handle,
    thread: Option<thread::JoinHandle<()>>,
}

impl SignalForwarding {
    pub(crate) fn install() -> Result<Self> {
        let mut signals = signal_hook::iterator::Signals::new([libc::SIGINT, libc::SIGTERM])
            .map_err(Error::Hardening)?;
        let handle = signals.handle();
        let child_pid = Arc::new(AtomicI32::new(0));
        let thread_child_pid = Arc::clone(&child_pid);
        let thread = thread::spawn(move || {
            for signal in signals.forever() {
                let pid = thread_child_pid.load(Ordering::SeqCst);
                if pid > 0 {
                    // SAFETY: `pid` is captured from the successfully spawned child process and
                    // `signal` comes from the signal-hook iterator for installed signals.
                    unsafe {
                        libc::kill(pid, signal);
                    }
                }
            }
        });

        Ok(Self {
            child_pid,
            handle,
            thread: Some(thread),
        })
    }

    pub(crate) fn set_child(&self, child_id: u32) {
        self.child_pid.store(child_id as i32, Ordering::SeqCst);
    }

    fn stop(&mut self) {
        self.child_pid.store(0, Ordering::SeqCst);
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SignalForwarding {
    fn drop(&mut self) {
        self.stop();
    }
}
