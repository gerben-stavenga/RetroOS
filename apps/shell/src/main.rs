use std::io::{self, Write, BufRead};
use std::process::Command;

fn run(name: &str, args: &[&str]) {
    match Command::new(name).args(args).status() {
        Ok(status) => {
            if !status.success() {
                if let Some(code) = status.code() {
                    eprintln!("{}: exited with code {}", name, code);
                }
            }
        }
        Err(e) => eprintln!("{}: {}", name, e),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // If args beyond argv[0], run as a command and exit
    if args.len() > 1 {
        let name = &args[1];
        let rest: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
        run(name, &rest);
        return;
    }

    println!("RetroOS shell\nType 'help' for commands.");
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush().ok();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            _ => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let name = parts[0];
        let rest = &parts[1..];

        match name {
            "exit" => return,
            "help" => {
                println!("  cd <dir>    - change directory");
                println!("  pwd         - print working directory");
                println!("  cat <file>  - print file contents");
                println!("  <file>      - run program");
                println!("  exit        - exit shell");
            }
            "cd" => {
                let dir = if rest.is_empty() { "/" } else { rest[0] };
                if let Err(e) = std::env::set_current_dir(dir) {
                    eprintln!("cd: {}: {}", dir, e);
                }
            }
            "pwd" => {
                match std::env::current_dir() {
                    Ok(p) => println!("{}", p.display()),
                    Err(e) => eprintln!("pwd: {}", e),
                }
            }
            "cat" => {
                for f in rest {
                    match std::fs::read(f) {
                        Ok(data) => { io::stdout().write_all(&data).ok(); }
                        Err(e) => eprintln!("cat: {}: {}", f, e),
                    }
                }
            }
            _ => run(name, rest),
        }
    }
}
