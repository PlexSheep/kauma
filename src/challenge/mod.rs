pub mod c1;
pub mod c2;

use std::fmt::{Debug, Display};

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait ChallengeLike<'de>: Serialize + Debug + Sized {
    type Solution: SolutionLike<'de>;
    fn solve(&self) -> Result<Self::Solution>;
}
pub trait SolutionLike<'de>: Deserialize<'de> + Debug + Display + Sized {}

pub fn run_challenge<'a>(raw_json: &serde_json::Value) -> Result<()> {
    // TODO: depending on the JSON format, decide which exact challenge to call, call it, and print
    // the solution to stdout
    todo!()
}
