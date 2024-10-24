//! Debug actions

use anyhow::Result;

use crate::settings::Settings;

use super::{Action, Testcase};

#[allow(unreachable_code)]
pub fn run_testcase(testcase: &Testcase, _settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::SD_Timeout => loop {
            std::thread::sleep(std::time::Duration::MAX);
        },
        _ => unreachable!(),
    })
}
