use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use getopts::Options;
use kauma_analyzer::challenge::Action;
use kauma_analyzer::settings::Settings;
use serde_json::{json, Value};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::FloatingFrees);
    opts.optopt("t", "threads", "set how many threads to use", "THREADS");
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "verbose", "print verbose output menu");
    opts.optflag(
        "V",
        "version",
        &format!("print the version of {}", env!("CARGO_PKG_NAME")),
    );
    opts.optopt(
        "a",
        "action",
        "set an action without inputting a JSON challenge definition, requires args to be set",
        "ACTION",
    );
    opts.optopt("d", "args", "additional arguments for the action", "ARGS");

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

    let mut settings = Settings::default();
    if matches.opt_present("verbose") {
        settings.verbose = true;
    }

    settings.threads = opt_num(&opts, &args, "threads");

    let instructions: Value;
    if let Some(raw) = matches.opt_str("action") {
        let args: serde_json::Value = if let Some(s) = matches.opt_str("args") {
            match serde_json::from_str(&s) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ARGS are invalid JSON: {e}");
                    usage_and_exit(&opts, &program)
                }
            }
        } else {
            eprintln!("ARGS are required with ACTION.");
            usage_and_exit(&opts, &program)
        };

        let action: Action = match serde_json::from_str(&format!("\"{raw}\"")) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Unable to parse '{raw}' as action:\n{e:#}");
                usage_and_exit(&opts, &program)
            }
        };

        if !matches.free.is_empty() {
            eprintln!("No CHALLENGE allowed with ACTION");
            usage_and_exit(&opts, &program)
        }
        let dummy_uuid = uuid::Uuid::default();
        instructions = json!({
            "testcases": {
            dummy_uuid: {
                "action": action,
                "arguments": args
            }
        }
        });

        if settings.verbose {
            eprintln!("? {instructions}")
        }
    } else {
        if matches.free.len() != 1 {
            eprintln!("Too many positional arguments, only one is allowed.");
            usage_and_exit(&opts, &program)
        }

        let raw_text: String = if matches.free[0] == "-" {
            if settings.verbose {
                eprintln!("? Reading from stdin");
            }
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
        instructions = match serde_json::from_str(&raw_text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "! Could not parse the text of the challenge definition file as JSON: {e}"
                );
                usage_and_exit(&opts, &program)
            }
        };
    }

    println!(
        "{:#}",
        kauma_analyzer::challenge::run_challenges(&instructions, settings)?
    );

    Ok(())
}

// `!` is a pseudo type and means the function will never return
fn usage_and_exit(opts: &Options, program: &str) -> ! {
    eprintln!("{} CHALLENGE", opts.short_usage(program));
    std::process::exit(1);
}

pub fn opt_num(opts: &Options, args: &Vec<String>, key: &str) -> Option<usize> {
    let matches = opts.parse(args).unwrap();
    let program = &args[0];
    matches.opt_str(key).map(|raw| match raw.parse() {
        Ok(t) => {
            if t < 1 {
                eprintln!("Cannot run with less than 1 thread");
                usage_and_exit(opts, program);
            }
            t
        }
        Err(e) => {
            eprintln!("could not parse -{key}: {e}");
            usage_and_exit(opts, program);
        }
    })
}
