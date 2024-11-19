use std::fmt::Write;
use std::net::ToSocketAddrs;

use getopts::{Matches, Options};

use padsim::{decrypt_and_unpad, len_to_const_arr, Server};

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<_> = std::env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::FloatingFrees);
    opts.optflag("h", "help", "print this help menu");
    opts.optflag(
        "V",
        "version",
        &format!("print the version of {}", env!("CARGO_PKG_NAME")),
    );
    opts.optopt("k", "key", "key to use, 16 bytes", "KEY");
    opts.optopt("a", "addr", "Hostname and port to run on", "HOST:PORT");
    opts.optopt("e", "encrypt", "Encrypt something", "BYTES");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            usage_and_exit(&opts, &program);
        }
    };

    if matches.opt_present("help") {
        usage_and_exit(&opts, &program);
    }

    if matches.opt_present("version") {
        eprintln!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    if !matches.opt_present("key") {
        eprintln!("key, not defined");
        usage_and_exit(&opts, &program);
    }

    let key: [u8; 16] = len_to_const_arr(&decode_hex(&get_str(&matches, "key"))?)
        .inspect_err(|_| eprintln!("error while loading the key"))?;

    if matches.opt_present("encrypt") {
        let pt: Vec<u8> = decode_hex(&get_str(&matches, "encrypt"))
            .inspect_err(|_| eprintln!("error while loading the plaintext"))?;
        let a = padsim::encrypt(&pt, &key);
        assert_eq!(
            pt.to_vec(),
            decrypt_and_unpad(&a, &key).expect("fuck cant decrypt")
        );
        assert!(a.len() == 16 || a.len() == 32);
        println!("{}", encode_hex(&a));
        std::process::exit(0);
    }

    if !matches.opt_present("addr") {
        eprintln!("addr not defined");
        usage_and_exit(&opts, &program);
    }

    let addr_raw = get_str(&matches, "addr");
    let addr = addr_raw.to_socket_addrs()?.next().expect("no socket addr");

    let serv = Server::new(&key);
    Ok(serv.run(addr)?)
}

fn get_str(o: &Matches, key: &str) -> String {
    o.opt_get(key)
        .expect("err with options")
        .expect("req arg not there")
}

///  Hex encoded [String] to [byte](u8) slice
///
/// Strips the `0x` prefix if it's there and adjusts for hex numbers where the leading 0 is left
/// out. Also ignores underscores which can be used for readability.
fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let mut s: String = s.to_string();
    s = s.replace("_", "");
    if s.starts_with("0x") {
        s = s.strip_prefix("0x").unwrap().into();
    }
    if s.len() % 2 == 1 {
        s = format!("0{s}");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// [Byte](u8) slice to hex encoded [String]
fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

// `!` is a pseudo type and means the function will never return
fn usage_and_exit(opts: &Options, program: &str) -> ! {
    eprintln!("{}", opts.short_usage(program));
    std::process::exit(1);
}
