pub mod cipher;
pub mod debug;
pub mod example;
pub mod ffield;

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::common::tag_json_value;
use crate::settings::Settings;

pub type ChallengeKey = String;
pub type ManyTestcases = HashMap<ChallengeKey, Testcase>;
pub type Response = serde_json::Value;
pub type ManyResponses = HashMap<ChallengeKey, Response>;

/// Describes what we should do and with what arguments
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Testcase {
    action: Action,
    arguments: serde_json::Value,
}

/// Describes how a testcase should be solved, as well as which arguments it should have.
///
/// # Self Defined [Actions](Action)
///
/// All [Actions](Action) beginning with `SD_` are **SELF DEFINED** and therefore not part of the assignment.
/// They are not guaranteed to work correctly, so use them at your own risk.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)] // allow SD_ANY naming
#[non_exhaustive] // who knows how many of these buggers there will be
pub enum Action {
    // example items //////////////////////////////////////////////////////////////////////////////
    /// Add 2 numbers together
    ///
    /// # Arguments
    ///
    /// - `number1`: [i64]
    /// - `number2`: [i64]
    ///
    /// # Returns
    ///
    /// `number1` + `number2` : [i64]
    #[serde(rename = "add_numbers")]
    AddNumbers,
    /// Subtract one number from another
    ///
    /// # Arguments
    ///
    /// - `number1`: [i64]
    /// - `number2`: [i64]
    ///
    /// # Returns
    ///
    /// `number1` - `number2` : [i64]
    #[serde(rename = "subtract_numbers")]
    SubNumbers,

    // ffield items ///////////////////////////////////////////////////////////////////////////////
    /// given a list of coefficients and a semantic, convert a polynomial to machine representation (a number)
    ///
    /// # Arguments
    ///
    /// - `semantic`: [Semantic](ffield::Semantic) - which kind of field to use
    /// - `coefficients`: [`Vec<u8>`] - exponents of the α's for the polynomial.
    ///
    /// # Returns
    ///
    /// Numeric representation of the polynomial described by `coefficients` : [Polynomial](ffield::Polynomial)
    Poly2Block,
    /// given a machine representation of a polynomial and a semantic, convert the polynomial into just
    /// it's coefficients
    ///
    /// # Arguments
    ///
    /// - `semantic`: [Semantic](ffield::Semantic) - which kind of field to use
    /// - `block`: [String] - Base64 string encoding a [u128]/[Polynomial](ffield::Polynomial)
    ///
    /// # Returns
    ///
    ///  Exponents of the α's for the polynomial : [`Vec<u8>`]
    Block2Poly,
    /// Multiply two polynomials in [F_2_128](ffield::F_2_128)
    ///
    /// # Arguments
    ///
    /// - `semantic`: [Semantic](ffield::Semantic) - which kind of field to use
    /// - `a`: [String] - Base64 string encoding a [Polynomial](ffield::Polynomial)
    /// - `b`: [String] - Base64 string encoding a [Polynomial](ffield::Polynomial)
    ///
    /// # Returns
    ///
    ///  `a` * `b` in the finite field for that semantic encoded in Base64 : [String]
    GfMul,
    /// Display a polynomial block with it's math representation
    ///
    /// # Arguments
    ///
    /// - `semantic`: [Semantic](ffield::Semantic) - which kind of field to use
    /// - `block`: [String] - Base64 string encoding a [Polynomial](ffield::Polynomial)
    ///
    /// # Returns
    ///
    /// The [Polynomial](ffield::Polynomial) defined by `block` in mathematical representation
    /// : [String]
    SD_DisplayPolyBlock,

    // cipher items ///////////////////////////////////////////////////////////////////////////////
    /// encrypt or decrypt a single block with a special AES version (sea128)
    ///
    /// # Arguments
    ///
    /// - `mode`: [Mode](cipher::Mode) - encrypt or decrypt
    /// - `key`: [String] - Base64 string encoding a `[u8; 16]`
    /// - `input`: [String] - Base64 string encoding a `[u8; 16]`
    ///
    /// # Returns
    ///
    ///  `input` encrypted or decrypted with `key` : Base64 string encoding a `[u8; 16]`
    Sea128,
    /// encrypt or decrypt a single block with a special AES version (sea128) in XEX mode
    ///
    /// # Arguments
    ///
    /// - `mode`: [Mode](cipher::Mode) - encrypt or decrypt
    /// - `key`: [String] - Base64 string encoding a `[u8; 32]`
    /// - `input`: [String] - Base64 string encoding a [`Vec<u8>`] whith length being $n \cdot 16$.
    /// - `tweak`: [String] - Base64 string encoding a `[u8; 16]`
    ///
    /// # Returns
    ///
    ///  `input` with `tweak` encrypted or decrypted with `key` : Base64 string encoding a [`Vec<u8>`]
    Xex,

    // debug items ////////////////////////////////////////////////////////////////////////////////
    /// wait indefinitely, job should eventually be killed
    SD_Timeout,
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
            Self::SD_DisplayPolyBlock => "poly",
            Self::Xex => "output",
            Self::SD_Timeout => unreachable!(),
        }
    }
}

pub fn run_challenges(
    raw_json: &serde_json::Value,
    settings: Settings,
) -> Result<serde_json::Value> {
    let testcases: ManyTestcases = serde_json::from_value(raw_json["testcases"].clone())?;
    let answers = Arc::new(Mutex::new(ManyResponses::new()));

    let pool = match settings.threads {
        Some(threads) => threadpool::ThreadPool::new(threads),
        None => threadpool::ThreadPool::default(),
    };

    let (tx, rx) = std::sync::mpsc::channel();
    for (key, testcase) in testcases.clone() {
        let tx = tx.clone();
        let answers_clone = answers.clone();
        let testcase = testcase.clone();
        pool.execute(move || {
            tx.send(challenge_runner(&testcase, answers_clone, &key, settings))
                .expect("could not send return value of thread to main thread")
        });
    }

    for _ in 0..testcases.len() {
        let result = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("! Job timed out: {e}");
                return Err(e.into());
            }
        };
        match result {
            Ok(_) => (),
            Err(e) => eprintln!("! failed to solve a challenge: {e:#}"),
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
    answers: Arc<Mutex<HashMap<ChallengeKey, serde_json::Value>>>,
    key: &ChallengeKey,
    settings: Settings,
) -> Result<()> {
    eprintln!("* starting challenge {key} ({})", testcase.action);
    if settings.verbose {
        eprintln!("? dumping challenge {key}\n{testcase:#}");
    }
    let sol = match testcase.action {
        Action::AddNumbers | Action::SubNumbers => example::run_testcase(testcase, settings),
        Action::Poly2Block | Action::Block2Poly | Action::GfMul | Action::SD_DisplayPolyBlock => {
            ffield::run_testcase(testcase, settings)
        }
        Action::Sea128 | Action::Xex => cipher::run_testcase(testcase, settings),
        Action::SD_Timeout => debug::run_testcase(testcase, settings),
    };
    if let Err(e) = sol {
        return Err(anyhow!("error while processing a testcase {key}: {e}"));
    }
    answers.lock().unwrap().insert(
        key.clone(),
        tag_json_value(testcase.action.solution_key(), sol.unwrap()),
    );
    eprintln!("* finished challenge {key} ({})", testcase.action);
    Ok(())
}
