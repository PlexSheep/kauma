use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, Default)]
pub struct Settings {
    pub verbose: bool,
    pub threads: Option<usize>,
}
