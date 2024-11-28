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
    sock.write_all(&(u8::MAX as u16 + 1).to_le_bytes())?;

    for o in 0..=u8::MAX {
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
    veprintln("response", format_args!("{results_raw:02x?}"));

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
    if idx < 1 {
        return Err(anyhow!(
            "Can't verify if the idx is < 1, as we need to prepend something to verify"
        ));
    }
    if candidates.is_empty() {
        return Err(anyhow!("No candidates at all given!"));
    } else if candidates.len() > 2 {
        return Err(anyhow!("Too many candidates than should be possible"));
    } else if candidates.len() == 1 {
        return Ok(candidates[0]);
    }
    let mut buf = Vec::with_capacity(2 + candidates.len() * 16);
    buf.extend((candidates.len() as u16).to_le_bytes());

    for candidate in candidates {
        let mut q = *base_q;
        q[idx] = *candidate;
        q[idx - 1] = 0xff;
        veprintln("q for {candidate:02x}", format_args!("{q:02x?}"));
        buf.extend(q);
    }

    sock.write_all(&buf)?;
    let mut responses: Vec<u8> = vec![0; candidates.len()];
    sock.read_exact(&mut responses)?;
    veprintln("response", format_args!("{responses:02x?}"));

    if responses.len() != candidates.len() {
        return Err(anyhow!("Server sent bad amount of response bytes"));
    }

    // logic only needs to work for len==2
    if candidates[0] == 1 {
        Ok(candidates[0])
    } else if candidates[1] == 1 {
        Ok(candidates[1])
    } else {
        return Err(anyhow!("Server says none of the candidates were correct"));
    }
}

fn abuse_padding_oracle(
    addr: SocketAddr,
    iv: &[u8; 16],
    ciphertext: &[u8], // somehow not 16 byte guarantee?, Assume 16 bytes for now
    verbose: bool,
) -> Result<Vec<u8>> {
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
    let chunks = ciphertext.chunks_exact(16);
    assert!(chunks.remainder().is_empty());
    let ciphertext_blocks: Vec<[u8; 16]> = chunks
        .map(|a| len_to_const_arr(a).expect("bad length of array despite chunks_exact"))
        .collect();

    for (block_idx, block) in ciphertext_blocks.iter().enumerate() {
        eprintln!("? ======= New Block");
        let cipher_block: [u8; 16] = len_to_const_arr(block)?;
        let mut intermediate_block: [u8; 16] = [0; 16];
        let mut plain_block: [u8; 16] = [0; 16];
        let mut sock = TcpStream::connect(addr).map_err(|e| {
            eprintln!("Could not connect to {addr}: {e}");
            e
        })?;
        sock.write_all(&cipher_block)?;

        // iterate last byte to first byte
        for byte_idx in (0usize..16usize).rev() {
            eprintln!("? ==== Next Byte");
            veprintln("byte_idx", format_args!("{byte_idx}"));
            veprintln("intermediate", format_args!("{intermediate_block:02x?}"));
            veprintln("plain", format_args!("{plain_block:02x?}"));

            let padding: u8 = 16 - byte_idx as u8;
            let mut q: [u8; 16] = [0; 16];
            let candidates;
            let correct_candidate: u8;

            if byte_idx == 15 {
                veprintln("base q", format_args!("{q:02x?}"));
                candidates = try_all_q(&mut sock, &q, byte_idx)?;
                veprintln("candidates", format_args!("{candidates:02x?}"));
                assert!(candidates.len() <= 2);

                correct_candidate = verify_candidate(&mut sock, &q, byte_idx, &candidates)?;
                veprintln("correct", format_args!("{correct_candidate:02x}"));
            } else {
                for g in (byte_idx + 1)..16 {
                    q[g] = intermediate_block[g] ^ padding;
                    eprintln!(
                        "g={g}\tint={:02x}\tpad={:02x}\tq={}",
                        intermediate_block[g], padding, q[g]
                    );
                }
                veprintln("base q", format_args!("{q:02x?}"));

                candidates = try_all_q(&mut sock, &q, byte_idx)?;
                veprintln("candidates", format_args!("{candidates:02x?}"));
                assert_eq!(candidates.len(), 1);
                correct_candidate = candidates[0];
            }
            intermediate_block[byte_idx] = correct_candidate ^ padding;
            if block_idx == 0 {
                plain_block[byte_idx] = intermediate_block[byte_idx] ^ iv[byte_idx];
            } else {
                plain_block[byte_idx] =
                    intermediate_block[byte_idx] ^ ciphertext_blocks[block_idx - 1][byte_idx];
            }
        }

        plaintext.extend(plain_block);
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
    fn test_crack_easy_0() {
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

    #[test]
    fn test_crack_easy_1() {
        const KEY: &[u8; 16] = &[
            0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa,
            0xbb, 0xaa,
        ];
        const PT: &[u8; 11] = &[
            0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x5f, 0x57, 0x4f, 0x52, 0x4c, 0x44,
        ];
        const PORT: u16 = 44001;

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

    #[test]
    fn test_crack_easy_2() {
        const KEY: &[u8; 16] = &[
            0x4c, 0xcf, 0x70, 0x83, 0xed, 0x85, 0x28, 0xf5, 0x11, 0xc2, 0x48, 0x5c, 0xf0, 0xa9,
            0x90, 0x13,
        ];
        const PT: &[u8; 15] = &[
            0xff, 0xaa, 0xff, 0xbb, 0xff, 0xaa, 0xff, 0xbb, 0xff, 0xaa, 0xff, 0xbb, 0xff, 0xaa,
            0xff, // padding: 0x01
        ];
        const PORT: u16 = 44001;

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

    #[test]
    fn test_crack_long() {
        const KEY: &[u8; 16] = &[
            0x4c, 0xcf, 0x70, 0x83, 0xed, 0x85, 0x28, 0xf5, 0x11, 0xc2, 0x48, 0x5c, 0xf0, 0xa9,
            0x90, 0x13,
        ];
        const PT: &[u8; 98] = &[
            0xb3, 0x65, 0x8f, 0x38, 0x12, 0x2f, 0xd7, 0x4e, 0xee, 0x68, 0xb7, 0xe7, 0x0f, 0x03,
            0x6f, 0xec, 0xe6, 0x30, 0xcb, 0x7c, 0x47, 0x7a, 0x93, 0x0a, 0xbb, 0x3d, 0xf3, 0xa3,
            0x5a, 0x56, 0x6f, 0xb9, 0xb3, 0x74, 0x8f, 0x29, 0x12, 0x3e, 0xd7, 0x5f, 0xee, 0x79,
            0xb7, 0xf6, 0x0f, 0x56, 0x3a, 0xec, 0xf7, 0x30, 0xda, 0x7c, 0x56, 0x7a, 0x82, 0x0a,
            0xaa, 0x3d, 0xe2, 0xa3, 0x0f, 0x03, 0x6f, 0xa8, 0xb3, 0x65, 0x8f, 0x38, 0x12, 0x2f,
            0xd7, 0x4e, 0xee, 0x68, 0xb7, 0xa3, 0x5a, 0x56, 0x2b, 0xec, 0xe6, 0x30, 0xcb, 0x7c,
            0x47, 0x7a, 0x93, 0x0a, 0xbb, 0x3d, 0x4e, 0x5a, 0xf6, 0xaf, 0x96, 0x15, 0xAA, 0xBB,
        ];
        const PORT: u16 = 44001;

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
