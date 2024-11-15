use block_padding::{Pkcs7, RawPadding, UnpadError};

/// pad with pkcs7
pub fn pad(data: &[u8]) -> Vec<u8> {
    eprintln!("data.len: {}", data.len());
    let mut buf: Vec<u8> = data.to_vec();
    while buf.len() % 16 != 0 || (data.len() % 16 == 0 && buf.len() < data.len() + 16) {
        buf.push(0xff);
    }
    eprintln!("buf {buf:02x?}");
    eprintln!("buf.len: {}", buf.len());

    Pkcs7::raw_pad(&mut buf, data.len());
    buf
}

/// unpad with pkcs7
pub fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
    Pkcs7::raw_unpad(data)
}

#[cfg(test)]
mod test {
    use block_padding::RawPadding;

    use super::*;

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
