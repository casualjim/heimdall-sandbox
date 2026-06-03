use std::ffi::{OsStr, OsString};

use crate::{Error, Result};

pub(crate) fn utf8_environment(
    environment: &[(OsString, OsString)],
) -> Result<Vec<(String, String)>> {
    environment
        .iter()
        .map(|(key, value)| Ok((utf8_os_str(key)?, utf8_os_str(value)?)))
        .collect()
}

fn utf8_os_str(value: &OsStr) -> Result<String> {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::unsupported_policy("microvm runtime requires UTF-8 environment"))
}
