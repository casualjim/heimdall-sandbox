use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

pub(crate) fn sandbox_name() -> Result<String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::platform(format!("system clock before Unix epoch: {error}")))?;
    Ok(format!(
        "heimdall-{}-{}",
        std::process::id(),
        elapsed.as_nanos()
    ))
}
