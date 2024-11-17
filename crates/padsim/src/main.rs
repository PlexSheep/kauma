use std::net::ToSocketAddrs;

use getopts::{Matches, Options};

use padsim::{len_to_const_arr, Server};

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
    opts.optopt("s", "solution", "plaintext that is to be guessed", "SOL");
    opts.optopt("a", "addr", "Hostname and port to run on", "HOST:PORT");

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

    if !(matches.opt_present("key")
        && matches.opt_present("solution")
        && matches.opt_present("addr"))
    {
        eprintln!("key, solution and/or addr not defined");
        usage_and_exit(&opts, &program);
    }

    let sol: Vec<u8> = decode_hex(&get_str(&matches, "solution"))?;
    let key: [u8; 16] = len_to_const_arr(&decode_hex(&get_str(&matches, "key"))?)
        .inspect_err(|_| eprintln!("error while loading the key"))?;
    let addr_raw = get_str(&matches, "addr");
    let addr = addr_raw.to_socket_addrs()?.next().expect("no socket addr");

    let serv = Server::new(&sol, &key);
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

// `!` is a pseudo type and means the function will never return
fn usage_and_exit(opts: &Options, program: &str) -> ! {
    eprintln!("{}", opts.short_usage(program));
    std::process::exit(1);
}
