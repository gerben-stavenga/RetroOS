use std::io::{Read,Write};
fn main() {
    println!("KEYBOARD READY"); std::io::stdout().flush().unwrap();
    let mut text = Vec::new();
    for byte in std::io::stdin().bytes() {
        let byte = byte.unwrap(); text.push(byte);
        if byte == b'\n' { break; }
    }
    print!("KEYBOARD LINUX ");
    for byte in text { print!("{byte:02X} "); }
    println!();
}
