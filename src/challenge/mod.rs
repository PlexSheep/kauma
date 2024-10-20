pub mod example;
pub mod ffield;

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common::tag_json_value;

pub type ManyTestcases = HashMap<Uuid, Testcase>;
pub type Response = serde_json::Value;
pub type ManyResponses = HashMap<Uuid, Response>;

/// Describes what we should do and with what arguments
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Testcase {
    action: Action,
    arguments: serde_json::Value,
}

/// Describes what we should do
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    // example items
    /// Add 2 numbers together
    #[serde(rename = "add_numbers")]
    AddNumbers,
    /// Substract one number from another
    #[serde(rename = "subtract_numbers")]
    SubNumbers,

    // ffield items
    /// given a list of coefficients and a semantic, convert a polynom to machine representation (a number)
    Poly2Block,
    /// given a machine representation of a polynom and a semantic, convert the polynom into just
    /// it's coefficients
    Block2Poly,
    /// Multiply two polynomials in [F_2_128](ffield::F_2_128)
    GfMul,
}

impl Default for Testcase {
    fn default() -> Self {
        Testcase {
            action: Action::AddNumbers,
            arguments: serde_json::json!({"number1": 1, "number2":2}),
        }
    }
}

impl Display for Testcase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).expect("could not serialize testcase for printing")
        )
    }
}

impl Action {
    pub const fn solution_key(self) -> &'static str {
        match self {
            Self::AddNumbers => "sum",
            Self::SubNumbers => "difference",
            Self::Poly2Block => "block",
            Self::Block2Poly => "coefficients",
            Self::GfMul => "product",
        }
    }
}

pub fn run_challenges(raw_json: &serde_json::Value) -> Result<serde_json::Value> {
    let testcases: ManyTestcases = serde_json::from_value(raw_json["testcases"].clone())?;
    let answers = Arc::new(Mutex::new(ManyResponses::new()));
    let mut handles: Vec<thread::JoinHandle<std::result::Result<(), anyhow::Error>>> = Vec::new();
    for (uuid, testcase) in testcases {
        let answer_mutex = answers.clone();
        eprintln!("* starting challenge {uuid}");
        handles.push(thread::spawn(move || {
            let sol = match testcase.action {
                Action::AddNumbers | Action::SubNumbers => example::run_testcase(&testcase),
                Action::Poly2Block | Action::Block2Poly | Action::GfMul => {
                    ffield::run_testcase(&testcase)
                }
            };
            if let Err(e) = sol {
                return Err(anyhow!("error while processing a testcase {uuid}: {e}"));
            }
            answer_mutex.lock().unwrap().insert(
                uuid,
                tag_json_value(testcase.action.solution_key(), sol.unwrap()),
            );
            eprintln!("* finished challenge {uuid}");
            Ok(())
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(inner_result) => {
                eprintln!("? joined a thread");
                match inner_result {
                    Ok(_) => (),
                    Err(e) => eprintln!("! failed to solve a challenge: {e:#?}"),
                }
            }
            Err(e) => eprintln!("! failed to solve a challenge: {e:#?}"),
        }
    }
    let responses = answers.lock().unwrap().clone();
    Ok(tag_json_value(
        "responses",
        serde_json::to_value(&responses)?,
    ))
}
