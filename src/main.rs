use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use getopts::Options;
use serde_json::Value;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::FloatingFrees);
    opts.optopt("t", "threads", "set how many threads to use", "THREADS");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            usage_and_exit(&opts, &program);
        }
    };

    if matches.opt_present("h") {
        usage_and_exit(&opts, &program);
    }

    let threads = opt_num(&opts, &args, "t");

    if matches.free.len() != 1 {
        eprintln!("Too many positional arguments, only one is allowed.");
        usage_and_exit(&opts, &program)
    }

    let raw_text: String = if matches.free[0] == "-" {
        eprintln!("? Reading from stdin");
        let mut buf: String = String::new();
        let _len = match std::io::stdin().read_to_string(&mut buf) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Could not read the challenge definition from stdin: {e}");
                usage_and_exit(&opts, &program);
            }
        };
        buf
    } else {
        let path: PathBuf = matches.free[0].clone().into();
        eprintln!("* Path of the challenge definition: {:?}", path);
        eprintln!("* Reading the challenge definition into memory");

        match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Could not read the challenge definition file: {e}");
                usage_and_exit(&opts, &program)
            }
        }
    };
    let json_value: Value = match serde_json::from_str(&raw_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("! Could not parse the text of the challenge definition file as JSON: {e}");
            usage_and_exit(&opts, &program)
        }
    };

    println!(
        "{:#}",
        kauma_analyzer::challenge::run_challenges(&json_value, threads)?
    );

    Ok(())
}

fn usage_and_exit(opts: &Options, program: &str) -> ! {
    eprintln!("{} CHALLENGE", opts.short_usage(program));
    std::process::exit(1);
}

pub fn opt_num(opts: &Options, args: &Vec<String>, short: &str) -> Option<usize> {
    let matches = opts.parse(args).unwrap();
    let program = &args[0];
    matches.opt_str(short).map(|raw| match raw.parse() {
        Ok(t) => {
            if t < 1 {
                eprintln!("Cannot run with less than 1 thread");
                usage_and_exit(opts, program);
            }
            t
        }
        Err(e) => {
            eprintln!("could not parse -{short}: {e}");
            usage_and_exit(opts, program);
        }
    })
}
