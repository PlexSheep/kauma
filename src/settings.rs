use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub verbose: bool,
    pub threads: Option<usize>,
}

pub const DEFAULT_SETTINGS: Settings = Settings {
    verbose: false,
    threads: None,
};

impl Default for Settings {
    fn default() -> Self {
        DEFAULT_SETTINGS
    }
}
