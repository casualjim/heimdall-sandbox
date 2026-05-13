use std::process::{ExitCode, Termination};

fn main() -> Status {
    Status(heimdall_sandbox::run())
}

struct Status(i32);

impl Termination for Status {
    fn report(self) -> ExitCode {
        ExitCode::from(self.0 as u8)
    }
}
