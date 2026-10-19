#![no_std]
#![no_main]
mod environment;
use core::arch::asm;
use environment::Environment;

// Keep this launcher i486/no_std. The kernel supplies clean Linux entry
// settings; session policy belongs here. execve children inherit their env.
unsafe fn cstr<'a>(pointer: *const u8) -> Result<&'a [u8], ()> {
    for len in 0..32768 {
        if unsafe { *pointer.add(len) } == 0 {
            return Ok(unsafe { core::slice::from_raw_parts(pointer, len) });
        }
    }
    Err(())
}
fn exec(path: *const u8, argv: &[*const u8], envp: &[*const u8]) -> i32 {
    let result;
    unsafe {
        asm!("int 0x80", inout("eax") 11i32 => result,
             in("ebx") path, in("ecx") argv.as_ptr(), in("edx") envp.as_ptr(), options(nostack));
    }
    result
}
fn launch(argc: i32, argv: *const *const u8, inherited: *const *const u8) -> Result<i32, ()> {
    let mut env = Environment::new();
    if !inherited.is_null() {
        let mut count = 0;
        loop {
            let entry = unsafe { *inherited.add(count) };
            if entry.is_null() { break; }
            if count == 128 { return Err(()); }
            env.insert(unsafe { cstr(entry)? })?;
            count += 1;
        }
    }
    env.finish()?;
    let mut args = [core::ptr::null(); 129];
    if !(0..=128).contains(&argc) { return Err(()); }
    let shell = env.get(b"SHELL").ok_or(())?;
    args[0] = if shell == b"/bin/sh" { b"sh\0".as_ptr() }
        else { shell.rsplit(|&b| b == b'/').next().ok_or(())?.as_ptr() };
    for (i, slot) in args.iter_mut().enumerate().take(argc as usize).skip(1) { *slot = unsafe { *argv.add(i) }; }
    let pointers = env.pointers();
    let result = exec(shell.as_ptr(), &args, &pointers);
    if shell == b"/bin/sh" && matches!(result, -2 | -8) { exec(b"/bin/busybox\0".as_ptr(), &args, &pointers); }
    Ok(127)
}
#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    match launch(argc, argv, envp) {
        Ok(code) => code,
        Err(()) => {
            let message = b"shell.elf: invalid or oversized Linux environment\n";
            unsafe { asm!("int 0x80", inout("eax") 4i32 => _, in("ebx") 2,
                          in("ecx") message.as_ptr(), in("edx") message.len(), options(nostack)); }
            126
        }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
