//! Debug actions

use anyhow::Result;

use crate::settings::Settings;

use super::{Action, Testcase};

pub fn run_testcase(testcase: &Testcase, _settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::SD_Timeout => loop {
            std::thread::sleep(std::time::Duration::MAX);
        },
        _ => unreachable!(),
    })
}
