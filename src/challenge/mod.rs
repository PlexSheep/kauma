pub mod ffield;

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type ManyTestcases = HashMap<Uuid, Testcase>;
pub type Response = serde_json::Value;
pub type ManyResponses = HashMap<Uuid, Response>;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Testcase {
    action: Action,
    arguments: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    // Example stuff
    #[serde(rename = "add_numbers")]
    AddNumbers,
    #[serde(rename = "subtract_numbers")]
    SubNumbers,
}

pub trait ChallengeLike<'de>: Serialize + Debug + Sized {
    type Solution: SolutionLike<'de>;
    fn solve(&self, action: Action) -> Result<Self::Solution>;
}
pub trait SolutionLike<'de>: Deserialize<'de> + Debug + Display + Sized {}

impl Default for Testcase {
    fn default() -> Self {
        Testcase {
            action: Action::AddNumbers,
            arguments: serde_json::json!({"number1": 1, "number2":2}),
        }
    }
}

impl Action {
    pub const fn solution_key(self) -> &'static str {
        match self {
            Self::AddNumbers { .. } => "sum",
            Self::SubNumbers { .. } => "difference",
        }
    }
}

pub fn run_challenges(raw_json: &serde_json::Value) -> Result<serde_json::Value> {
    let testcases: ManyTestcases = serde_json::from_value(raw_json["testcases"].clone())?;
    let answers = Arc::new(Mutex::new(ManyResponses::new()));
    for (uuid, testcase) in testcases {
        let answer_mutex = answers.clone();
        thread::spawn(move || {
            answer_mutex.lock().unwrap().insert(
                uuid,
                match testcase.action {
                    Action::AddNumbers => ffield::run_testcase(&testcase),
                    Action::SubNumbers => ffield::run_testcase(&testcase),
                },
            )
        });
    }

    let mut helper_map = serde_json::Map::new();
    helper_map.insert(
        "responses".to_owned(),
        serde_json::to_value(answers.lock().unwrap().clone())?,
    );
    Ok(serde_json::Value::Object(helper_map))
}
