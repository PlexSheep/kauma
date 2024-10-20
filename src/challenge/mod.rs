pub mod cipher;
pub mod example;
pub mod ffield;

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common::tag_json_value;

pub type ManyTestcases = HashMap<Uuid, Testcase>;
pub type Response = serde_json::Value;
pub type ManyResponses = HashMap<Uuid, Response>;

const ENV_THREAD_NUM: &str = "KAUMA_THREADS";

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

    // cipher items
    /// encrypt or decrypt with a special aes version (sea128)
    Sea128,
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
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
            Self::Sea128 => "output",
        }
    }
}

pub fn run_challenges(raw_json: &serde_json::Value) -> Result<serde_json::Value> {
    let testcases: ManyTestcases = serde_json::from_value(raw_json["testcases"].clone())?;
    let answers = Arc::new(Mutex::new(ManyResponses::new()));

    let threads: Option<usize> = match std::env::var(ENV_THREAD_NUM) {
        Ok(v) => match v.parse() {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("! Could not parse ENV_THREAD_NUM: {e}");
                None
            }
        },
        Err(e) => {
            // it's only an error if the variable is defined but somehow bad
            if !(e == std::env::VarError::NotPresent) {
                eprintln!("! Could not read ENV_THREAD_NUM from environment: {e}");
            }
            None
        }
    };

    let pool = threadpool::ThreadPool::new(threads.unwrap_or(num_cpus::get()));

    let (tx, rx) = std::sync::mpsc::channel();
    for (uuid, testcase) in testcases.clone() {
        let tx = tx.clone();
        let answers_clone = answers.clone();
        let testcase = testcase.clone();
        pool.execute(move || {
            tx.send(challenge_runner(&testcase, answers_clone, &uuid))
                .expect("could not send return value of thread to main thread")
        });
    }

    for result in rx.iter().take(testcases.len()) {
        eprintln!("? joined a thread");
        match result {
            Ok(_) => (),
            Err(e) => eprintln!("! failed to solve a challenge: {e:#?}"),
        }
    }

    let responses = answers.lock().unwrap().clone();
    Ok(tag_json_value(
        "responses",
        serde_json::to_value(&responses)?,
    ))
}

fn challenge_runner(
    testcase: &Testcase,
    answers: Arc<Mutex<HashMap<Uuid, serde_json::Value>>>,
    uuid: &Uuid,
) -> Result<()> {
    eprintln!("* starting challenge {uuid} ({})", testcase.action);
    let sol = match testcase.action {
        Action::AddNumbers | Action::SubNumbers => example::run_testcase(testcase),
        Action::Poly2Block | Action::Block2Poly | Action::GfMul => ffield::run_testcase(testcase),
        Action::Sea128 => cipher::run_testcase(testcase),
    };
    if let Err(e) = sol {
        return Err(anyhow!("error while processing a testcase {uuid}: {e}"));
    }
    answers.lock().unwrap().insert(
        *uuid,
        tag_json_value(testcase.action.solution_key(), sol.unwrap()),
    );
    eprintln!("* finished challenge {uuid} ({})", testcase.action);
    Ok(())
}
