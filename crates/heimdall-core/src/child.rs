use std::process::{Child, ExitStatus};

use crate::{Error, Result};

pub(crate) struct ChildGuard {
    child: Child,
    completed: bool,
}

impl ChildGuard {
    pub(crate) fn new(child: Child) -> Self {
        Self {
            child,
            completed: false,
        }
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn wait(&mut self) -> Result<ExitStatus> {
        let status = self.child.wait().map_err(Error::Wait)?;
        self.completed = true;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
