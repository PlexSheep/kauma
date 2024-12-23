pub mod cipher;
pub mod debug;
pub mod example;
pub mod ffield;
pub mod pad;
pub mod polyfactor;
pub mod superpoly;

use std::collections::HashMap;
use std::fmt::{Debug, Display};

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
#[serde(rename_all = "snake_case")]
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
    #[serde(rename = "poly2block")]
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
    #[serde(rename = "block2poly")]
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
    #[serde(rename = "gfmul")]
    GfMul,
    /// Divide two polynomials in [F_2_128](ffield::F_2_128)
    ///
    /// # Arguments
    ///
    /// - `a`: [String] - Base64 string encoding a [Polynomial](ffield::Polynomial)
    /// - `b`: [String] - Base64 string encoding a [Polynomial](ffield::Polynomial) (never 0)
    ///
    /// Both in [ffield::Semantic::Gcm].
    ///
    /// # Returns
    ///
    ///  `a` / `b` in the finite field for that semantic encoded in Base64 : [String]
    #[serde(rename = "gfdiv")]
    GfDiv,
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
    #[serde(rename = "sd_displaypolyblock")]
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
    /// encrypt any amount of blocks with AES-GCM
    ///
    /// # Arguments
    ///
    /// - `algorithm`: [String] - string representation of the [PrimitiveAlgorithm](cipher::PrimitiveAlgorithm) to use
    /// - `nonce`: [String] - Base64 string encoding a `[u8;12]`
    /// - `key`: [String] - Base64 string encoding a `[u8;16]`
    /// - `plaintext`: [String] - Base64 string encoding a [`Vec<u8>`]
    /// - `ad`: [String] - Base64 string encoding a [`Vec<u8>`]
    ///
    /// # Returns
    ///
    /// Multiple values.
    ///
    /// - `ciphertext`: [String] - Base64 string encoding a [`Vec<u8>`]
    /// - `tag`: [String] - Base64 string encoding a [`[u8;16]`]
    /// - `L`: [String] - Base64 string encoding a [`[u8;16]`]
    /// - `H`: [String] - Base64 string encoding a [`[u8;16]`]
    GcmEncrypt,
    /// decrypt any amount of blocks with AES-GCM
    ///
    /// # Arguments
    ///
    /// - `algorithm`: [String] - string representation of the [PrimitiveAlgorithm](cipher::PrimitiveAlgorithm) to use
    /// - `nonce`: [String] - Base64 string encoding a `[u8;12]`
    /// - `key`: [String] - Base64 string encoding a `[u8;16]`
    /// - `ciphertext`: [String] - Base64 string encoding a [`Vec<u8>`]
    /// - `ad`: [String] - Base64 string encoding a [`Vec<u8>`]
    /// - `tag`: [String] - Base64 string encoding a `[u8;16]`
    ///
    /// # Returns
    ///
    /// Multiple values.
    ///
    /// - `plaintext`: [String] - Base64 string encoding a [`Vec<u8>`]
    /// - `authentic`: [bool] - Was the given input authentic?
    GcmDecrypt,

    /// Make a side channel attack with a padding oracle
    ///
    /// # Arguments
    ///
    /// - `hostname`: [String] - the host where the custom server is hosted
    /// - `port`: [i32] - network port of the other host
    /// - `iv`: [String] - Base64 string encoding a [`[u8;16]`]
    /// - `ciphertext`: [String] - Base64 string encoding a [`Vec<u8>`]
    ///
    /// # Returns
    ///
    ///  `plaintext` that can be exfiltrated by abusing the padding oracle : Base64 string encoding a [`Vec<u8>`]
    PaddingOracle,

    /// Add two [`SuperPoly`](superpoly::SuperPoly)s
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// # Arguments
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    /// - `B`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///    making a [SuperPoly](superpoly::SuperPoly)
    ///
    /// # Returns
    ///
    /// - `S`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), sum of `A` and `B`
    #[serde(rename = "gfpoly_add")]
    GfpolyAdd,
    /// Multiply two [`SuperPoly`](superpoly::SuperPoly)s
    ///
    /// # Arguments
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    /// - `B`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///    making a [SuperPoly](superpoly::SuperPoly)
    ///
    /// # Returns
    ///
    /// - `S`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), product of `A` and `B`
    #[serde(rename = "gfpoly_mul")]
    GfpolyMul,
    /// Exponentiate a [`SuperPoly`](superpoly::SuperPoly)
    ///
    /// # Arguments
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), this is the base
    /// - `k`: [`i64`] - the exponentiant
    ///
    /// # Returns
    ///
    /// - `S`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), product of `A` and `B`
    #[serde(rename = "gfpoly_pow")]
    GfpolyPow,
    /// Divide a [`SuperPoly`](superpoly::SuperPoly) by another, with remainder
    ///
    /// # Arguments
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    /// - `B`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///    making a [SuperPoly](superpoly::SuperPoly) (never zero I think)
    ///
    /// # Returns
    ///
    /// With A = Q * B + R :
    ///
    /// - `Q`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    /// - `R`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    #[serde(rename = "gfpoly_divmod")]
    GfpolyDivMod,
    /// Compute the modular exponentiation Z = A^k mod M of a polynomial
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// # Arguments
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), the base
    /// - `M`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), the modulus
    /// - `k`: [u64] - the exponent
    ///
    /// # Returns
    ///
    /// - `Z`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), result of A^k mod M
    #[serde(rename = "gfpoly_powmod")]
    GfpolyPowMod,
    /// Sort a list of polynomials according to total ordering rules
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// # Arguments
    ///
    /// - `polys`: list of polynomials, each represented as `[[String]]` list of Base64 string encoding [Polynomials](ffield::Polynomial)
    ///
    /// # Returns
    ///
    /// - `sorted_polys`: list of polynomials sorted according to total ordering rules
    #[serde(rename = "gfpoly_sort")]
    GfpolySort,
    /// Convert a polynomial to monic form by dividing all coefficients by the leading coefficient
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// # Arguments
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    ///
    /// # Returns
    ///
    /// - `A*`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), the monic form of A
    #[serde(rename = "gfpoly_make_monic")]
    GfpolyMakeMonic,
    /// Calculate the square root of a polynomial Q where Q only has coefficients for even exponents of X
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// # Arguments
    ///
    /// - `Q`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly) that only has coefficients for even powers
    ///
    /// # Returns
    ///
    /// - `S`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), where S^2 = Q
    #[serde(rename = "gfpoly_sqrt")]
    GfpolySqrt,
    /// Calculate the derivative of a polynomial F
    ///
    /// Uses [Semantic::Gcm].
    ///
    /// # Arguments
    ///
    /// - `F`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    ///
    /// # Returns
    ///
    /// - `F'`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), the derivative of F
    #[serde(rename = "gfpoly_diff")]
    GfpolyDiff,
    /// Calculate the greatest common divisor (GCD) of two polynomials A and B
    ///
    /// Uses [Semantic::Gcm].
    ///
    /// # Arguments
    ///
    /// - `A`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    /// - `B`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly)
    ///
    /// # Returns
    ///
    /// - `G`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), the monic GCD of A and B
    #[serde(rename = "gfpoly_gcd")]
    GfpolyGcd,
    /// Squarefree factorization of a polynomial
    ///
    /// Uses [Semantic::Gcm](ffield::Semantic::Gcm).
    ///
    /// # Arguments
    ///
    /// - `F`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///   making a [SuperPoly](superpoly::SuperPoly), the polynomial to factor
    ///
    /// # Returns
    ///
    /// - `factors`: list of objects containing:
    ///   - `factor`: `[[String]]` - list of Base64 string encoding [Polynomials](ffield::Polynomial),
    ///     making a [SuperPoly](superpoly::SuperPoly), a squarefree factor
    ///   - `exponent`: [u32] - the multiplicity of this factor
    #[serde(rename = "gfpoly_factor_sff")]
    GfpolyFactorSff,
    /// Calculate equal-degree factorization using Cantor-Zassenhaus algorithm
    ///
    /// # Arguments
    ///
    /// - `F`: `[String]` - list of Base64 string encoding Polynomials,
    ///   making a SuperPoly that is a product of irreducible polynomials of degree d
    /// - `d`: [usize] - The degree of the irreducible polynomials
    ///
    /// # Returns
    ///
    /// - `factors`: `[[String]]` - list of polynomials that are the irreducible factors
    #[serde(rename = "gfpoly_factor_edf")]
    GfpolyFactorEdf,

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
    pub const fn solution_key(self) -> Option<&'static str> {
        Some(match self {
            Self::AddNumbers => "sum",
            Self::SubNumbers => "difference",
            Self::Poly2Block => "block",
            Self::Block2Poly => "coefficients",
            Self::GfMul => "product",
            Self::GfDiv => "q",
            Self::Sea128 => "output",
            Self::SD_DisplayPolyBlock => "poly",
            Self::Xex => "output",
            Self::GcmEncrypt => return None,
            Self::GcmDecrypt => return None,
            Self::SD_Timeout => unreachable!(),
            Self::PaddingOracle => "plaintext",
            Self::GfpolyAdd => "S",
            Self::GfpolyMul => "P",
            Self::GfpolyPow => "Z",
            Self::GfpolyPowMod => "Z",
            Self::GfpolySort => "sorted_polys",
            Self::GfpolySqrt => "S",
            Self::GfpolyDivMod => return None,
            Self::GfpolyMakeMonic => "A*",
            Self::GfpolyDiff => "F'",
            Self::GfpolyGcd => "G",
            Self::GfpolyFactorSff => "factors",
            Self::GfpolyFactorEdf => "factors",
        })
    }
}

fn run_challenges_st(testcases: &ManyTestcases, settings: Settings) -> Result<serde_json::Value> {
    let mut answers = ManyResponses::new();
    for (key, testcase) in testcases {
        answers.insert(
            key.to_string(),
            challenge_runner(testcase, key, settings)?.1,
        );
    }

    Ok(tag_json_value("responses", serde_json::to_value(&answers)?))
}

fn run_challenges_mt(testcases: &ManyTestcases, settings: Settings) -> Result<serde_json::Value> {
    let mut answers = ManyResponses::new();
    let pool = match settings.threads {
        Some(threads) => threadpool::ThreadPool::new(threads),
        None => threadpool::ThreadPool::default(),
    };

    let (tx, rx) = std::sync::mpsc::channel();
    for (key, testcase) in testcases.clone() {
        let tx = tx.clone();
        let testcase = testcase.clone();
        pool.execute(move || {
            tx.send(challenge_runner(&testcase, &key, settings))
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
            Ok(v) => {
                let _ = answers.insert(v.0.to_string(), v.1);
            }
            Err(e) => {
                eprintln!("! failed to solve a challenge: {e:#}");
                continue;
            }
        }
    }

    Ok(tag_json_value("responses", serde_json::to_value(&answers)?))
}

pub fn run_challenges(
    raw_json: &serde_json::Value,
    settings: Settings,
) -> Result<serde_json::Value> {
    let testcases: ManyTestcases = serde_json::from_value(raw_json["testcases"].clone())?;

    let cpus = num_cpus::get();
    eprintln!("* cpus: {cpus}");
    if cpus > 1 && settings.threads.map(|t| t != 1).unwrap_or(true) && testcases.len() > 1 {
        eprintln!("* Running in multi threaded mode");
        run_challenges_mt(&testcases, settings)
    } else {
        eprintln!("* Running in single threaded mode");
        run_challenges_st(&testcases, settings)
    }
}

fn challenge_runner(
    testcase: &Testcase,
    key: &ChallengeKey,
    settings: Settings,
) -> Result<(ChallengeKey, Response)> {
    if settings.verbose {
        eprintln!("* starting challenge {key} ({})", testcase.action);
    }
    let sol = match testcase.action {
        Action::AddNumbers | Action::SubNumbers => example::run_testcase(testcase, settings),
        Action::Poly2Block
        | Action::Block2Poly
        | Action::GfMul
        | Action::GfDiv
        | Action::SD_DisplayPolyBlock => ffield::run_testcase(testcase, settings),
        Action::Sea128 | Action::Xex | Action::GcmEncrypt | Action::GcmDecrypt => {
            cipher::run_testcase(testcase, settings)
        }
        Action::SD_Timeout => debug::run_testcase(testcase, settings),
        Action::PaddingOracle => pad::run_testcase(testcase, settings),
        Action::GfpolyAdd
        | Action::GfpolyMul
        | Action::GfpolyPow
        | Action::GfpolyDivMod
        | Action::GfpolySort
        | Action::GfpolySqrt
        | Action::GfpolyMakeMonic
        | Action::GfpolyDiff
        | Action::GfpolyGcd
        | Action::GfpolyPowMod => superpoly::run_testcase(testcase, settings),
        Action::GfpolyFactorSff | Action::GfpolyFactorEdf => {
            polyfactor::run_testcase(testcase, settings)
        }
    };
    if let Err(e) = sol {
        return Err(anyhow!("error while processing a testcase {key}: {e}"));
    }
    if settings.verbose {
        eprintln!("* finished challenge {key} ({})", testcase.action);
    }

    Ok((
        key.to_string(),
        if let Some(t) = testcase.action.solution_key() {
            tag_json_value(t, sol.unwrap())
        } else {
            sol.unwrap()
        },
    ))
}
