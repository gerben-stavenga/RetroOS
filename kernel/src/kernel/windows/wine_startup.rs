//! Shared Wine process initialization before DLL_PROCESS_ATTACH for PE and NE.
use super::*;

pub(super) fn emit_call(code: &mut Vec<u8>, address: u32, arguments: &[u32]) {
    for value in arguments.iter().rev() {
        code.push(0x68);
        code.extend_from_slice(&value.to_le_bytes());
    }
    code.push(0xb8);
    code.extend_from_slice(&address.to_le_bytes());
    code.extend_from_slice(&[0xff, 0xd0]);
}

pub(super) fn bootstrap<A: crate::Arch>(
    machine: &mut A,
    modules: &[Module],
    first: usize,
    attach: u32,
    abort: u32,
    mut code: Vec<u8>,
) -> Result<u32, i32> {
    const BOOTSTRAP: u32 = 0x7ff5_0000;
    const NAMES: u32 = 0x7ff7_0000;
    emit_call(
        &mut code,
        export_address(modules, b"NTDLL", b"RetroWineInitializePeb")?,
        &[],
    );
    let register = export_address(modules, b"NTDLL", b"RetroWineRegisterModule")?;
    let mut names = Vec::new();
    for module in modules.iter().skip(first) {
        let path = guest_windows_path(&module.path);
        let address = NAMES + names.len() as u32;
        for c in b"\\??\\"
            .iter()
            .chain(path.iter())
            .copied()
            .chain(core::iter::once(0))
        {
            names.extend_from_slice(&(c as u16).to_le_bytes());
        }
        emit_call(&mut code, register, &[module.base, address]);
        code.extend_from_slice(&[0x85, 0xc0, 0x74, 10, 0x50, 0xb8]);
        code.extend_from_slice(&abort.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0x0f, 0x0b]);
    }
    emit_call(
        &mut code,
        export_address(modules, b"NTDLL", b"RetroWineInitializeLocale")?,
        &[],
    );
    code.push(0x68);
    code.extend_from_slice(&attach.to_le_bytes());
    code.push(0xc3);
    if names.len() > 65536 || code.len() > 4096 {
        return Err(8);
    }
    machine.zero(NAMES as usize, 65536);
    machine.copy_to(NAMES as usize, &names);
    machine.set_page_flags(NAMES as usize / 4096, 16, false, false);
    machine.zero(BOOTSTRAP as usize, 4096);
    machine.copy_to(BOOTSTRAP as usize, &code);
    machine.set_page_flags(BOOTSTRAP as usize / 4096, 1, false, true);
    Ok(BOOTSTRAP)
}
