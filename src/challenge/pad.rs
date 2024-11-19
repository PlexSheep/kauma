use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use anyhow::Result;

use crate::common::interface::{get_any, get_bytes_maybe_hex, put_bytes};
use crate::common::{len_to_const_arr, veprintln};
use crate::settings::Settings;

use super::{Action, Testcase};

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

    eprintln!("? Sending Q blocks ({} Bytes)", buf.len() * 16);
    sock.write_all(flat_buf)?;
    sock.flush()?;
    eprintln!("? reading server response");
    sock.read_exact(&mut results_raw)?;
    eprintln!("? got server response");

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
    Ok(result)
}

fn abuse_padding_oracle(
    addr: SocketAddr,
    iv: &[u8; 16],
    ciphertext: &[u8], // somehow not 16 byte guarantee?, Assume 16 bytes for now
    verbose: bool,
) -> Result<[u8; 16]> {
    let mut sock = TcpStream::connect(addr).map_err(|e| {
        eprintln!("Could not connect to {addr}: {e}");
        e
    })?;
    let mut good_q = [0; 16];
    let mut plaintext = [0; 16];
    sock.write_all(ciphertext)?;

    for (idx, good_byte) in good_q.into_iter().enumerate().rev() {
        veprintln("guess idx", format_args!("{idx}"));
        let (a, b) = try_all_q(&mut sock, &good_q, idx)?;
        veprintln("a", format_args!("{a}"));
        veprintln("b", format_args!("{b:?}"));
        if let Some(b) = b {
            todo!()
        } else
        // padding must be [..., 0x01]
        {
            good_q[idx] = a;
            plaintext[idx] = good_q[idx] ^ ciphertext[idx]; // FIXME: this needs to be xored with
                                                            // the intermediate, not the ciphertext
            todo!()
        }
        veprintln("good_q", format_args!("{good_q:02x?}"));
        todo!()
    }

    Ok(plaintext)
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

    const TIMEOUT: Duration = Duration::from_millis(300);
    const HOST: &str = "localhost";

    fn start_serv(key: &[u8; 16], addr: SocketAddr) {
        let key = key.to_owned();
        std::thread::spawn(move || {
            let s = Server::new(&key);
            s.run(addr).expect("server fail");
        });
        std::thread::sleep(Duration::from_millis(20));
    }

    #[test]
    fn test_crack_easy() {
        const KEY: &[u8; 16] = &[
            0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa,
            0xbb, 0xaa,
        ];
        const PT: &[u8; 15] = &[
            0xff, 0xaa, 0xff, 0xbb, 0xff, 0xaa, 0xff, 0xbb, 0xff, 0xaa, 0xff, 0xbb, 0xff, 0xaa,
            0xff, // padding: 0x01
        ];
        const PORT: u16 = 44000;

        let sol = run_with_timeout(TIMEOUT, || {
            let addr = to_addr(HOST, PORT)?;
            start_serv(KEY, addr);
            let enc = padsim::encrypt(PT, KEY);
            abuse_padding_oracle(addr, &[0; 16], &enc, true)
        })
        .expect("timed out")
        .expect("abusing the oracle failed");

        assert_hex(&sol, PT);
    }
}
