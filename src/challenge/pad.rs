use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use anyhow::{anyhow, Result};

use crate::common::interface::{get_any, get_bytes_maybe_hex, put_bytes};
use crate::common::{len_to_const_arr, veprintln};
use crate::settings::Settings;

use super::{Action, Testcase};

fn try_all_q(sock: &mut TcpStream, base_q: &[u8; 16], idx: usize) -> Result<Vec<u8>> {
    let mut candidates = Vec::with_capacity(2);
    let mut results_raw = [0; u8::MAX as usize];
    let mut buf: Vec<[u8; 16]> = Vec::with_capacity(u8::MAX as usize);
    sock.write_all(&(u8::MAX as u16).to_le_bytes())?;

    for o in 0..u8::MAX {
        let mut q = *base_q;
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

    for (i, r) in results_raw.iter().enumerate() {
        if *r == 0 {
            continue;
        } else {
            candidates.push(i as u8);
        }
    }
    Ok(candidates)
}

fn verify_candidate(
    sock: &mut TcpStream,
    base_q: &[u8; 16],
    idx: usize,
    candidates: &[u8],
) -> Result<u8> {
    if candidates.is_empty() {
        return Err(anyhow!("No candidates at all given!"));
    }
    todo!()
}

fn abuse_padding_oracle(
    addr: SocketAddr,
    iv: &[u8; 16],
    ciphertext: &[u8], // somehow not 16 byte guarantee?, Assume 16 bytes for now
    verbose: bool,
) -> Result<Vec<u8>> {
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
    let mut counter = 1;
    let chunks = ciphertext.chunks_exact(16);
    assert!(chunks.remainder().is_empty());
    let ciphertext_blocks: Vec<[u8; 16]> = chunks
        .map(|a| len_to_const_arr(a).expect("bad length of array despite chunks_exact"))
        .collect();

    for block in ciphertext_blocks.iter() {
        eprintln!("? ======= New Block");
        let block: [u8; 16] = len_to_const_arr(block)?;
        let mut intermediate_block: [u8; 16] = [0; 16];
        let mut plain_block: [u8; 16] = [0; 16];
        let mut sock = TcpStream::connect(addr).map_err(|e| {
            eprintln!("Could not connect to {addr}: {e}");
            e
        })?;
        sock.write_all(&block)?;

        // iterate last byte to first byte
        for byte_idx in (0usize..16usize).rev() {
            eprintln!("? ==== Next Byte");
            veprintln("byte_idx", format_args!("{byte_idx}"));

            let padding: u8 = 16 - byte_idx as u8;
            let mut q: [u8; 16] = [0; 16];

            for g in 0..16 {
                q[g] = intermediate_block[g] ^ padding;
            }
            veprintln("base q", format_args!("{q:02x?}"));

            let candidates = try_all_q(&mut sock, &q, byte_idx)?;
            veprintln("candidates", format_args!("{candidates:02x?}"));

            let correct_candidate = if candidates.len() == 1 {
                candidates[0]
            } else {
                verify_candidate(&mut sock, &q, byte_idx, &candidates)?
            };
            veprintln("correct", format_args!("{correct_candidate:02x}"));

            intermediate_block[byte_idx] = correct_candidate ^ padding;
            if counter == 0 {
                plain_block[byte_idx] = intermediate_block[byte_idx] ^ iv[byte_idx];
            } else {
                plain_block[byte_idx] =
                    intermediate_block[byte_idx] ^ ciphertext_blocks[counter - 1][byte_idx];
            }
        }

        plaintext.extend(plain_block);
        counter += 1;
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

    const TIMEOUT: Duration = Duration::from_millis(3000);
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
