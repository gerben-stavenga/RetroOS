#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn main() {
    crt::print("Hello from init!\n");
}
