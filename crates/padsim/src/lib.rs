use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

use block_padding::{Pkcs7, UnpadError};

pub const DEFAULT_KEY: &[u8; 16] = b"genericarraysbad";

/// stolen from the block_padding crate
///
/// kauma-analyzer runs in a very constrained environment, where I can not add arbitrary
/// dependencies. Padsim is just a dev-dependency for testing, but cargo needs to resolve all
/// dependencies, so I cannot use block_padding directly.
mod block_padding {
    #[derive(Debug)]
    pub struct UnpadError;
    #[derive(Debug)]
    pub struct Pkcs7;
    impl Pkcs7 {
        #[inline]
        pub fn raw_pad(block: &mut [u8], pos: usize) {
            if block.len() > 255 {
                panic!("block size is too big for PKCS#7");
            }
            if pos >= block.len() {
                panic!("`pos` is bigger or equal to block size");
            }
            let n = (block.len() - pos) as u8;
            for b in &mut block[pos..] {
                *b = n;
            }
        }

        #[inline]
        pub fn raw_unpad(block: &[u8], strict: bool) -> Result<&[u8], UnpadError> {
            if block.len() > 255 {
                panic!("block size is too big for PKCS#7");
            }
            let bs = block.len();
            let n = block[bs - 1];
            if n == 0 || n as usize > bs {
                return Err(UnpadError);
            }
            let s = bs - n as usize;
            if strict && block[s..bs - 1].iter().any(|&v| v != n) {
                return Err(UnpadError);
            }
            Ok(&block[..s])
        }
    }
}

/// pad with pkcs7
pub fn pad(data: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = data.to_vec();
    while buf.len() % 16 != 0 || (data.len() % 16 == 0 && buf.len() < data.len() + 16) {
        buf.push(0xff);
    }

    Pkcs7::raw_pad(&mut buf, data.len());
    buf
}

/// unpad with pkcs7
pub fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
    Pkcs7::raw_unpad(data, true)
}

/// encrypt with pcks7 and xor
pub fn encrypt(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let padded = pad(plain);

    let blocks: Vec<&[u8]> = padded.chunks(16).collect();
    let mut ciphertext = Vec::with_capacity(padded.len());

    for block in blocks {
        ciphertext.extend(xor_blocks(block, key));
    }

    ciphertext
}

/// decrypt with pcks7 and xor
pub fn decrypt_and_unpad(cipher: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, UnpadError> {
    let pt = decrypt(cipher, key);

    unpad(&pt).map(|a| a.to_vec())
}

pub fn decrypt(cipher: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let blocks: Vec<&[u8]> = cipher.chunks(16).collect();
    let mut plaintext = Vec::with_capacity(cipher.len());

    for block in blocks {
        plaintext.extend(xor_blocks(block, key));
    }

    plaintext
}

pub struct Server {
    q_queue: VecDeque<[u8; 16]>,
    q_wait: u16,
    key: [u8; 16],
    ciphertext: [u8; 16],
}

impl Server {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            q_queue: VecDeque::new(),
            q_wait: 0,
            key: *key,
            ciphertext: [0; 16],
        }
    }

    pub fn run(mut self, addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        println!("SERV: listening on {addr}");

        loop {
            let (stream, peer) = match listener.accept() {
                Err(e) => {
                    eprintln!("SERV: could not accept peer: {e}");
                    continue;
                }
                Ok(a) => a,
            };

            match self.handle_conn(stream, peer) {
                Ok(_) => {
                    println!("server stops...");
                    break;
                }
                Err(e) => {
                    eprintln!("SERV: error while handling connection with {peer}: {e}");
                    continue;
                }
            };
        }
        Ok(())
    }

    fn handle_conn(&mut self, mut stream: TcpStream, peer: SocketAddr) -> io::Result<()> {
        println!("SERV: handling {peer}");
        println!("SERV: awaiting ciphertext");
        let mut qlen_raw = [0; 2];
        stream.read_exact(&mut self.ciphertext)?;
        println!("SERV: got ciphertext: {:02x?}", self.ciphertext);
        println!(
            "SERV: decrypted: {:02x?}",
            decrypt(&self.ciphertext, &self.key)
        );

        loop {
            println!("SERV: expecting qlen next");
            stream.read_exact(&mut qlen_raw)?;
            self.q_wait = u16::from_le_bytes(qlen_raw);
            if self.q_wait == 0 {
                stream.shutdown(std::net::Shutdown::Both)?;
                return Ok(());
            }
            println!("SERV: expecting {} Q blocks next", self.q_wait);

            let mut qbuf: Vec<u8> = vec![0; self.q_wait as usize * 16];
            stream.read_exact(&mut qbuf)?;

            for i in (0..self.q_wait as usize).map(|i| i * 16) {
                let qb = &qbuf[i..i + 16];
                let qb: &[u8; 16] = &len_to_const_arr(qb)?;
                if let Some(msg) = self.push_q(qb) {
                    stream.write_all(&msg)?;
                }
            }
        }
    }

    fn push_q(&mut self, qb: &[u8; 16]) -> Option<Vec<u8>> {
        self.q_queue.push_back(*qb);
        self.q_wait -= 1;
        if self.q_wait == 0 {
            let answers = Some(self.evaluate_qs());
            self.q_queue.clear();
            answers
        } else {
            None
        }
    }

    #[allow(clippy::identity_op)] // helps readability
    fn evaluate_qs(&self) -> Vec<u8> {
        println!("SERV: got all Q's, evaluating...");
        let mut answers: Vec<u8> = Vec::with_capacity(self.q_queue.len());
        let mut pt: [u8; 16];
        let mut one_correct = false;

        for (idx, qb) in self.q_queue.iter().enumerate() {
            pt = len_to_const_arr(&decrypt(&self.ciphertext, &self.key))
                .expect("down casting from vec to [u8;16] error");
            pt = xor_blocks(&pt, qb);

            match unpad(&pt) {
                Ok(_) => {
                    one_correct = true;
                    answers.push(0x01);
                    println!("SERV: correct q: {qb:02x?}");
                    println!("SERV: leads to: {pt:02x?}");
                }
                Err(_unpad_err) => answers.push(0x00),
            }

            if !one_correct && idx == self.q_queue.len() - 1 {
                println!("SERV: No matches. Giving Example");
                println!("SERV: q: {qb:02x?}");
                println!("SERV: leads to: {pt:02x?}");
            }
        }
        println!("SERV: answers.len: {}", answers.len());
        assert!(answers.len() <= 256); // why should it ever be more?
        let correct: Vec<_> = answers
            .iter()
            .enumerate()
            .filter(|(_, v)| **v == 1)
            .map(|(i, _)| i)
            .collect();
        if !correct.is_empty() {
            println!(
                "SERV: first correct q: {:x?} (at {})",
                self.q_queue[correct[0]], correct[0]
            );
        } else if correct.len() == 2 {
            println!(
                "SERV: seconds correct q: {:x?} (at {})",
                self.q_queue[correct[1]], correct[1]
            );
        }
        answers
    }
}

fn xor_blocks(a: &[u8], b: &[u8]) -> [u8; 16] {
    assert!(a.len() == 16);
    assert!(b.len() == 16);
    let mut buf = [0; 16];
    for i in 0..16 {
        buf[i] = a[i] ^ b[i];
    }
    buf
}

/// Try to downcast any array of [u8] into an array of constant size
pub fn len_to_const_arr<const N: usize>(data: &[u8]) -> io::Result<[u8; N]> {
    let arr: [u8; N] = match data.try_into() {
        Ok(v) => v,
        Err(e) => {
            let e = io::Error::other(format!(
                "Data is of bad length {}: {:02x?} ; {e:#?}",
                data.len(),
                data
            ));
            return Err(e);
        }
    };
    Ok(arr)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_xor_blocks() {
        let my = [19; 16];
        let a = xor_blocks(&my, DEFAULT_KEY);
        assert_eq!(
            a,
            [116, 118, 125, 118, 97, 122, 112, 114, 97, 97, 114, 106, 96, 113, 114, 119]
        )
    }

    #[test]
    fn test_encrypt() {
        let my = [19; 16];
        let a = encrypt(&my, DEFAULT_KEY);
        assert_eq!(
            a,
            [
                116, 118, 125, 118, 97, 122, 112, 114, 97, 97, 114, 106, 96, 113, 114, 119, 119,
                117, 126, 117, 98, 121, 115, 113, 98, 98, 113, 105, 99, 114, 113, 116
            ]
        )
    }

    #[test]
    fn test_decrypt() {
        let my = [19; 16];
        let enc = [
            116, 118, 125, 118, 97, 122, 112, 114, 97, 97, 114, 106, 96, 113, 114, 119, 119, 117,
            126, 117, 98, 121, 115, 113, 98, 98, 113, 105, 99, 114, 113, 116,
        ];
        let a = decrypt_and_unpad(&enc, DEFAULT_KEY).expect("could not decrypt");
        assert_eq!(a, my);
    }

    #[test]
    fn test_encrypt_decrypt_0() {
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

        let a = encrypt(PT, KEY);
        let b = decrypt_and_unpad(&a, KEY).expect("could not decrypt");
        assert_eq!(PT.to_vec(), b);
    }

    #[test]
    fn test_encrypt_decrypt_1() {
        let my = [19; 16];
        let a = encrypt(&my, DEFAULT_KEY);
        let b = decrypt_and_unpad(&a, DEFAULT_KEY).expect("could not decrypt");
        assert_eq!(my.to_vec(), b);
    }

    #[test]
    fn test_pad_lib() {
        const MSG: &[u8; 11] = b"this is msg";
        const PADDED: &[u8; 16] = b"this is msg\x05\x05\x05\x05\x05";
        let mut buf: Vec<u8> = MSG.to_vec();
        while buf.len() % 16 != 0 {
            buf.push(0xff);
        }
        Pkcs7::raw_pad(&mut buf, MSG.len());
        assert_eq!(&buf, PADDED)
    }

    #[test]
    fn test_unpad_lib() {
        const MSG: &[u8] = b"this is msg";
        const PADDED: &[u8; 16] = b"this is msg\x05\x05\x05\x05\x05";
        let unpadded = Pkcs7::raw_unpad(PADDED, true).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    #[should_panic]
    fn test_unpad_lib_crap() {
        const MSG: &[u8] = b"this is msg";
        const PADDED: &[u8; 16] = b"this is msg\x05\x06\x06\x06\x06";
        let unpadded = Pkcs7::raw_unpad(PADDED, true).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    fn test_pad() {
        const MSG: &[u8; 11] = b"so nen m\xFCll";
        const PAD: &[u8; 16] = b"so nen m\xFCll\x05\x05\x05\x05\x05";
        let padded = pad(MSG);
        assert_eq!(&padded, PAD)
    }

    #[test]
    fn test_pad_long() {
        const MSG: &[u8; 47] = b"das ist ein ganz ganz ganzts langaaaaaaaar text";
        const PAD: &[u8; 48] = b"das ist ein ganz ganz ganzts langaaaaaaaar text\x01";
        let padded = pad(MSG);
        assert_eq!(&padded, PAD)
    }

    #[test]
    fn test_pad_full() {
        const MSG: &[u8; 48] = b"das ist ein ganz ganz ganzts langaaaaaaaar textA";
        const PAD: &[u8; 64] = b"das ist ein ganz ganz ganzts langaaaaaaaar textA\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
        let unpadded = unpad(PAD).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    fn test_unpad() {
        const MSG: &[u8; 11] = b"so nen m\xFCll";
        const PAD: &[u8; 16] = b"so nen m\xFCll\x05\x05\x05\x05\x05";
        let unpadded = unpad(PAD).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    #[should_panic]
    fn test_unpad_crap() {
        const MSG: &[u8; 11] = b"so nen m\xFCll";
        const PAD: &[u8; 16] = b"so nen m\xFCll\x05\x05\x05\x06\x05";
        let unpadded = unpad(PAD).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    fn test_unpad_long() {
        const MSG: &[u8; 47] = b"das ist ein ganz ganz ganzts langaaaaaaaar text";
        const PAD: &[u8; 48] = b"das ist ein ganz ganz ganzts langaaaaaaaar text\x01";
        let unpadded = unpad(PAD).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    fn test_unpad_full() {
        const MSG: &[u8; 48] = b"das ist ein ganz ganz ganzts langaaaaaaaar textA";
        const PAD: &[u8; 64] = b"das ist ein ganz ganz ganzts langaaaaaaaar textA\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
        let unpadded = unpad(PAD).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }
}
