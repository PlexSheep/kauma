use anyhow::Result;

use crate::common::interface::{get_bytes_maybe_hex, get_int, get_str, put_bytes};
use crate::common::len_to_const_arr;
use crate::settings::Settings;

use super::{Action, Testcase};

fn abuse_padding_oracle(
    host: &str,
    port: i64,
    iv: &[u8; 16],
    ct: &[u8],
    verbose: bool,
) -> Result<Vec<u8>> {
    Ok(vec![0, 0, 0, 1])
}

pub fn run_testcase(testcase: &Testcase, settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::PaddingOracle => {
            let host: String = get_str(&testcase.arguments, "hostname")?;
            let port: i64 = get_int(&testcase.arguments, "port")?;
            let iv: [u8; 16] = len_to_const_arr(&get_bytes_maybe_hex(&testcase.arguments, "iv")?)?;
            let ct: Vec<u8> = get_bytes_maybe_hex(&testcase.arguments, "ciphertext")?;

            put_bytes(&abuse_padding_oracle(
                &host,
                port,
                &iv,
                &ct,
                settings.verbose,
            )?)?
        }
        _ => unreachable!(),
    })
}
