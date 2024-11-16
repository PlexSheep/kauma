use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

use block_padding::{Pkcs7, RawPadding, UnpadError};

pub const DEFAULT_KEY: &[u8; 16] = b"genericarraysbad";

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
    Pkcs7::raw_unpad(data)
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
pub fn decrypt(cipher: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, UnpadError> {
    let blocks: Vec<&[u8]> = cipher.chunks(16).collect();
    let mut plaintext = Vec::with_capacity(cipher.len());

    for block in blocks {
        plaintext.extend(xor_blocks(block, key));
    }

    unpad(&plaintext).map(|a| a.to_vec())
}

pub struct Server {
    solution: Vec<u8>,
    q_queue: VecDeque<[u8; 16]>,
    q_wait: u16,
    key: [u8; 16],
    ciphertext: [u8; 16],
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Status {
    Continue,
    Stop,
}

impl Server {
    pub fn new(sol: &[u8], key: &[u8; 16]) -> Self {
        Self {
            solution: sol.to_vec(),
            q_queue: VecDeque::new(),
            q_wait: 0,
            key: *key,
            ciphertext: [0; 16],
        }
    }

    pub fn run(mut self, addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        println!("listening on {addr}");

        loop {
            let (stream, peer) = listener.accept()?;
            if self.handle_conn(stream, peer)? == Status::Stop {
                println!("server stops...");
                break;
            }
        }
        Ok(())
    }

    fn handle_conn(&mut self, mut stream: TcpStream, peer: SocketAddr) -> io::Result<Status> {
        println!("handling {peer}");
        let mut qlen_raw = [0; 2];
        stream.read_exact(&mut self.ciphertext)?;

        loop {
            println!("expecting qlen next");
            stream.read_exact(&mut qlen_raw)?;
            self.q_wait = u16::from_le_bytes(qlen_raw);
            if self.q_wait == 0 {
                return Ok(Status::Stop);
            }
            println!("expecting {} Q blocks next", self.q_wait);

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
        self.q_queue.push_front(*qb);
        self.q_wait -= 1;
        if self.q_wait == 0 {
            Some(self.evaluate_qs())
        } else {
            None
        }
    }

    fn evaluate_qs(&self) -> Vec<u8> {
        let mut answers: Vec<u8> = Vec::with_capacity(self.q_queue.len());
        let mut pt: [u8; 16];
        for qb in &self.q_queue {
            pt = xor_blocks(&self.ciphertext, &self.key);
            pt = xor_blocks(&pt, qb);

            match unpad(&pt) {
                Ok(_) => answers.push(0x01),
                Err(_unpad_err) => answers.push(0x00),
            }
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
fn len_to_const_arr<const N: usize>(data: &[u8]) -> io::Result<[u8; N]> {
    let arr: [u8; N] = match data.try_into() {
        Ok(v) => v,
        Err(e) => {
            let e = io::Error::other(format!(
                "! Data is of bad length {}: {:02x?} ; {e:#?}",
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
        let a = decrypt(&enc, DEFAULT_KEY).expect("could not decrypt");
        assert_eq!(a, my);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let my = [19; 16];
        let a = encrypt(&my, DEFAULT_KEY);
        let b = decrypt(&a, DEFAULT_KEY).expect("could not decrypt");
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
        let unpadded = Pkcs7::raw_unpad(PADDED).expect("could not unpad");
        assert_eq!(unpadded, MSG)
    }

    #[test]
    #[should_panic]
    fn test_unpad_lib_crap() {
        const MSG: &[u8] = b"this is msg";
        const PADDED: &[u8; 16] = b"this is msg\x05\x06\x06\x06\x06";
        let unpadded = Pkcs7::raw_unpad(PADDED).expect("could not unpad");
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
