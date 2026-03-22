//! RetroOS interactive shell

#![no_std]
#![no_main]

fn run(path: &str, args: &[&str]) {
    let pid = crt::fork();
    if pid == 0 {
        crt::exec(path, args);
        crt::print("not found: ");
        crt::print(path);
        crt::print("\n");
        crt::exit(1);
    }
    crt::waitpid(pid);
}

#[unsafe(no_mangle)]
pub fn main(args: &[&str]) {
    // If args are given (beyond argv[0]), run them as a command and exit
    if args.len() > 1 {
        run(args[1], args);
        return;
    }

    crt::print("RetroOS shell\nType 'help' for commands.\n");
    let mut buf = [0u8; 128];
    loop {
        crt::print("> ");
        let len = crt::read_line(&mut buf);
        if len == 0 { continue; }

        // Trim whitespace
        let line = &buf[..len];
        let mut start = 0;
        let mut end = line.len();
        while start < end && line[start] == b' ' { start += 1; }
        while end > start && line[end - 1] == b' ' { end -= 1; }
        if start >= end { continue; }
        let trimmed = &line[start..end];

        // Safe: keyboard input is ASCII
        let cmd = unsafe { core::str::from_utf8_unchecked(trimmed) };

        // Split command and args at first space
        let (name, rest) = match cmd.find(' ') {
            Some(i) => (&cmd[..i], cmd[i+1..].trim_start()),
            None => (cmd, ""),
        };

        match name {
            "exit" => return,
            "help" => {
                crt::print("  cd <dir>    - change directory\n");
                crt::print("  pwd         - print working directory\n");
                crt::print("  stress [N]  - COW stress test (default depth 3)\n");
                crt::print("  hello       - run HELLO.COM in VM86 mode\n");
                crt::print("  <file>      - run .elf, .com, or .exe program\n");
                crt::print("  exit        - exit shell\n");
            }
            "cd" => {
                if rest.is_empty() {
                    // cd with no args goes to root
                    crt::chdir("/");
                } else {
                    let r = crt::chdir(rest);
                    if r < 0 {
                        crt::print("cd: no such directory: ");
                        crt::print(rest);
                        crt::print("\n");
                    }
                }
            }
            "pwd" => {
                let mut cwdbuf = [0u8; 64];
                let len = crt::getcwd(&mut cwdbuf);
                if len > 0 {
                    crt::print("/");
                    let s = unsafe { core::str::from_utf8_unchecked(&cwdbuf[..len as usize]) };
                    crt::print(s);
                    crt::print("\n");
                } else {
                    crt::print("/\n");
                }
            }
            "stress" => {
                let depth = if rest.is_empty() { "3" } else { rest };
                run("stress.elf", &["stress.elf", depth]);
            }
            "hello" => run("HELLO.COM", &["HELLO.COM"]),
            _ => run(name, &[cmd]),
        }
    }
}
