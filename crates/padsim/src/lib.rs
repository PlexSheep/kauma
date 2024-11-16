use block_padding::{Pkcs7, RawPadding, UnpadError};

const KEY: &[u8; 16] = b"genericarraysbad";

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

pub fn encrypt(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let padded = pad(plain);

    let blocks: Vec<&[u8]> = padded.chunks(16).collect();
    let mut ciphertext = Vec::with_capacity(padded.len());

    for block in blocks {
        ciphertext.extend(xor_blocks(block, key));
    }

    ciphertext
}

pub fn decrypt(cipher: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, UnpadError> {
    let blocks: Vec<&[u8]> = cipher.chunks(16).collect();
    let mut plaintext = Vec::with_capacity(cipher.len());

    for block in blocks {
        plaintext.extend(xor_blocks(block, key));
    }

    unpad(&plaintext).map(|a| a.to_vec())
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_xor_blocks() {
        let my = [19; 16];
        let a = xor_blocks(&my, KEY);
        assert_eq!(
            a,
            [116, 118, 125, 118, 97, 122, 112, 114, 97, 97, 114, 106, 96, 113, 114, 119]
        )
    }

    #[test]
    fn test_encrypt() {
        let my = [19; 16];
        let a = encrypt(&my, KEY);
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
        let a = decrypt(&enc, KEY).expect("could not decrypt");
        assert_eq!(a, my);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let my = [19; 16];
        let a = encrypt(&my, KEY);
        let b = decrypt(&a, KEY).expect("could not decrypt");
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
