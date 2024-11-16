use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::Result;

use crate::common::interface::{get_any, get_bytes_maybe_hex, put_bytes};
use crate::common::len_to_const_arr;
use crate::settings::Settings;

use super::{Action, Testcase};

fn abuse_padding_oracle(
    addr: SocketAddr,
    iv: &[u8; 16],
    ct: &[u8],
    verbose: bool,
) -> Result<Vec<u8>> {
    Ok(vec![0, 0, 0, 1])
}

pub fn run_testcase(testcase: &Testcase, settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::PaddingOracle => {
            let host: String = get_any(&testcase.arguments, "hostname")?;
            let port: u16 = get_any(&testcase.arguments, "port")?;
            let iv: [u8; 16] = len_to_const_arr(&get_bytes_maybe_hex(&testcase.arguments, "iv")?)?;
            let ct: Vec<u8> = get_bytes_maybe_hex(&testcase.arguments, "ciphertext")?;

            put_bytes(&abuse_padding_oracle(
                to_addr(&host, port)?,
                &iv,
                &ct,
                settings.verbose,
            )?)?
        }
        _ => unreachable!(),
    })
}

fn to_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let d = format!("{host}:{port}");
    Ok(d.to_socket_addrs()?.next().unwrap())
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use crate::common::{assert_hex, run_with_timeout};

    use super::*;
    use padsim::Server;

    const TIMEOUT: Duration = Duration::from_millis(500);
    const HOST: &str = "localhost";

    fn start_serv(sol: &[u8], key: &[u8; 16], addr: SocketAddr) {
        let sol = sol.to_owned();
        let key = key.to_owned();
        std::thread::spawn(move || {
            let s = Server::new(&sol, &key);
            s.run(addr).expect("server fail");
        });
    }

    #[test]
    fn test_crack_easy() {
        const KEY: &[u8; 16] = b"safkjsaflasgAAAA";
        const PT: &[u8; 14] = b"aaaaaaaaaaaaaa";
        const PORT: u16 = 44000;

        let sol = run_with_timeout(TIMEOUT, || {
            let addr = to_addr(HOST, PORT)?;
            start_serv(PT, KEY, addr);
            abuse_padding_oracle(addr, &[0; 16], &padsim::encrypt(PT, KEY), true)
        })
        .expect("timed out")
        .expect("abusing the oracle failed");

        assert_hex(&sol, PT);
    }
}
