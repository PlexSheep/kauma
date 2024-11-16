use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use anyhow::Result;

use crate::common::interface::{get_any, get_bytes_maybe_hex, put_bytes};
use crate::common::{len_to_const_arr, veprintln};
use crate::settings::Settings;

use super::{cipher, Action, Testcase};

fn try_all_q(sock: &mut TcpStream, good_q: &[u8; 16], idx: usize) -> Result<(u8, Option<u8>)> {
    const MAX: u8 = 255;
    let mut results_raw = [0; MAX as usize];
    let mut buf: Vec<[u8; 16]> = Vec::with_capacity(MAX as usize);
    sock.write_all(&(MAX as u16).to_le_bytes())?;

    for o in 0..MAX {
        let mut q = *good_q;
        q[idx] = o;
        buf.push(q);
    }

    let flat_buf = buf.as_flattened();

    sock.write_all(flat_buf)?;
    sock.flush()?;
    sock.read_exact(&mut results_raw)?;

    let mut result: (u8, Option<u8>) = (0, None);
    let mut found_one = false;
    veprintln("results_raw", format_args!("{results_raw:01x?}"));
    for (i, r) in results_raw.iter().enumerate() {
        if *r == 0 {
            continue;
        }
        if !found_one {
            result = (i as u8, result.1);
            found_one = true;
        } else {
            result = (result.0, Some(i as u8));
        }
    }
    veprintln("result", format_args!("{result:2x?}"));
    Ok(result)
}

fn abuse_padding_oracle(
    addr: SocketAddr,
    iv: &[u8; 16],
    ct: &[u8],
    verbose: bool,
) -> Result<Vec<u8>> {
    let mut sock = TcpStream::connect(addr)?;
    let mut good_q = [0; 16];
    sock.write_all(ct)?;

    for (idx, good_byte) in good_q.into_iter().enumerate().rev() {
        veprintln("guess idx", format_args!("{idx}"));
        let (a, b) = try_all_q(&mut sock, &good_q, idx)?;
        if let Some(b) = b {
            todo!()
        } else
        // padding must be [..., 0x01]
        {
            good_q[idx] = a;
            todo!()
        }
        veprintln("good_q", format_args!("{good_q:02x?}"));
        todo!()
    }

    let mut plaintext = [0; 16];
    for i in 0..16 {
        plaintext[i] = ct[i] ^ good_q[i];
    }

    Ok(vec![0, 1, 1, 3])
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
    use std::time::Duration;

    use crate::common::{assert_hex, run_with_timeout};

    use super::*;
    use padsim::Server;

    const TIMEOUT: Duration = Duration::from_millis(3000);
    const HOST: &str = "localhost";

    fn start_serv(sol: &[u8], key: &[u8; 16], addr: SocketAddr) {
        let sol = sol.to_owned();
        let key = key.to_owned();
        std::thread::spawn(move || {
            let s = Server::new(&sol, &key);
            s.run(addr).expect("server fail");
        });
        std::thread::sleep(Duration::from_millis(20));
    }

    #[test]
    fn test_crack_easy() {
        const KEY: &[u8; 16] = b"safkjsaflasgAAAA";
        const PT: &[u8; 14] = b"aaaaaaaaaaaaaa";
        const PORT: u16 = 44000;

        let sol = run_with_timeout(TIMEOUT, || {
            let addr = to_addr(HOST, PORT)?;
            start_serv(PT, KEY, addr);
            let enc = padsim::encrypt(PT, KEY);
            abuse_padding_oracle(addr, &[0; 16], &enc, true)
        })
        .expect("timed out")
        .expect("abusing the oracle failed");

        assert_hex(&sol, PT);
    }
}
