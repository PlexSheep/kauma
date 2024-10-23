//! This example takes care of the actions "add_numbers" and "subtract_numbers"
//!
//! It is an example implementation to easily see how the Challenge API works

use anyhow::{anyhow, Result};

use crate::settings::Settings;

use super::{Action, Testcase};

pub fn run_testcase(testcase: &Testcase, _settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::AddNumbers => {
            let (a, b) = get_numbers(&testcase.arguments)?;
            serde_json::to_value(a + b)?
        }
        Action::SubNumbers => {
            let (a, b) = get_numbers(&testcase.arguments)?;
            serde_json::to_value(a - b)?
        }
        _ => unreachable!(),
    })
}

fn get_numbers(args: &serde_json::Value) -> Result<(i64, i64)> {
    let a = args["number1"].clone();
    let b = args["number2"].clone();
    if !a.is_i64() && !b.is_i64() {
        return Err(anyhow!("either {a} or {b} are not a i128"));
    }
    Ok((
        a.as_number().unwrap().as_i64().unwrap(),
        b.as_number().unwrap().as_i64().unwrap(),
    ))
}
