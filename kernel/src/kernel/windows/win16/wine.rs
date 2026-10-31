//! Wine's existing relay assembly runs in userspace. This supplies its initial
//! selectors, stacks and TEB/PEB layout, and binds the embedded CALLFROM16 records.
use super::*;

const LDT_COPY: u32 = 0x7ff8_0000;
const ENTER16: u32 = 0x7ff3_0000;
use super::super::wine_startup::emit_call;

fn patch_calls(code: &mut [u8], normal: u32, registers: u32, flat_cs: u16) -> Result<usize, i32> {
    let mut offset = 0;
    while code.get(offset) == Some(&0x68) {
        let call = code.get_mut(offset..offset + 32).ok_or(-8)?;
        if call[5] != 0x9a { return Err(-8); }
        let register = matches!(u16::from_le_bytes([call[12], call[13]]), 0xca66 | 0xcb66);
        call[6..10].copy_from_slice(&if register { registers } else { normal }.to_le_bytes());
        call[10..12].copy_from_slice(&flat_cs.to_le_bytes());
        offset += 32;
    }
    if offset == 0 { return Err(-8); }
    Ok(offset / 32)
}

fn map_code<A: crate::Arch>(machine: &mut A, address: u32, bytes: &[u8]) -> Result<(), i32> {
    if bytes.len() > 4096 { return Err(-8); }
    machine.zero(address as usize, 4096);
    machine.copy_to(address as usize, bytes);
    machine.set_page_flags(address as usize / 4096, 1, false, true);
    Ok(())
}

pub(super) fn start<A: crate::Arch>(machine: &mut A, windows: &mut WindowsState,
    regs: &mut Regs, tid: usize, _target: &Regs) -> Result<(), i32>
{
    let normal = super::super::export_address(&windows.modules, b"KRNL386.EXE16", b"RetroWineCallFrom16")?;
    let registers = super::super::export_address(&windows.modules, b"KRNL386.EXE16", b"RetroWineCallFrom16Regs")?;
    let flat_cs = regs.code_seg();
    let flat_ds = regs.ds as u32;
    let teb = super::super::TEB_BASE;
    let peb = super::super::PEB_BASE;
    let params = super::super::PROCESS_DATA;
    windows.stack_size = 256 * 1024;
    windows.stack_base = super::super::STACK_TOP - windows.stack_size;
    machine.zero(windows.stack_base as usize, windows.stack_size as usize);
    machine.set_page_flags(windows.stack_base as usize / 4096, windows.stack_size as usize / 4096, true, false);
    for (address, size) in [(teb, super::super::TEB_SIZE), (peb, super::super::PEB_SIZE), (params, 4096)] {
        machine.zero(address as usize, size);
        machine.set_page_flags(address as usize / 4096, size / 4096, true, false);
    }
    // Wine keeps its default debug-channel options immediately after the PEB.
    machine.write::<u8>((peb + 4096) as usize, 7);
    let teb_selector = selector(&mut windows.ldt, teb, 4096, false)?;
    for (offset, value) in [(0, u32::MAX), (4, super::super::STACK_TOP), (8, windows.stack_base),
        (0x18, teb), (0x20, tid as u32 + 1), (0x24, tid as u32 + 1), (0x30, peb),
        (0x10c, super::super::STACK_TOP - 128), (0x1d8, 0)] {
        machine.write::<u32>((teb + offset) as usize, value);
    }
    super::super::initialize_teb_string(machine);
    // Both PE and NE launch paths supply Wine's normalized process strings.
    super::super::initialize_process_strings(machine,windows)?;
    super::super::initialize_environment(machine,windows)?;
    machine.write::<u32>((peb + 0x10) as usize, params);
    machine.write::<u32>((peb + 0x64) as usize, 1); // NumberOfProcessors
    machine.write::<u32>((peb + 0x220) as usize, LDT_COPY);
    machine.zero(LDT_COPY as usize, 65536);
    machine.set_page_flags(LDT_COPY as usize / 4096, 16, true, false);
    for (i, &desc) in windows.ldt.iter().enumerate() {
        let base = selector_base_from_ldt(&windows.ldt, i as u16 * 8 + 7).unwrap_or(0);
        let limit = ((desc & 0xffff) | ((desc >> 32) & 0xf0000)) as u32;
        let bits = limit | (((desc >> 40) as u32 & 0x1f) << 24)
            | (((desc >> 55) as u32 & 1) << 29) | (((desc >> 54) as u32 & 1) << 30);
        machine.write::<u32>(LDT_COPY as usize + i * 4, base);
        machine.write::<u32>(LDT_COPY as usize + 32768 + i * 4, bits);
    }
    let state = windows.win16.as_ref().ok_or(-8)?;
    for module in &state.modules {
        let Some((owner, _)) = &module.pe_owner else { continue; };
        let image = ne::Image::parse(&module.data).map_err(|_| -8)?;
        for number in 1..=image.header.segment_count {
            let segment = image.segment(number).map_err(|_| -8)?;
            if !segment.is_code() { continue; }
            let mut code = image.segment_bytes(segment).map_err(|_| -8)?.to_vec();
            patch_calls(&mut code, normal, registers, flat_cs)?;
            let address = module_segment_base(module.base, number)? as usize;
            machine.set_page_flags(address / 4096, code.len().div_ceil(4096), true, false);
            machine.copy_to(address, &code);
            machine.set_page_flags(address / 4096, code.len().div_ceil(4096), false, true);
        }
        // Wine's generated pointer-conversion helpers read the LDT-copy
        // pointer stored in the original PE descriptor's e_res2 field.
        let pe_module = windows.modules.iter().find(|m| m.base == *owner).ok_or(-8)?;
        let pe = super::super::pe::Image::parse(&pe_module.data).map_err(|_| -8)?;
        let (rva, _) = pe.embedded_ne().map_err(|_| -8)?.ok_or(-8)?;
        machine.write::<u32>((owner + rva + 40) as usize, LDT_COPY);
    }
    // Wine owns the initial NE task and enters through its normal callback
    // relay. A raw far jump skips TDB/TIB and module initialization.
    let abort = super::super::export_address(&windows.modules, b"RETROOS", b"RetroProcessExit")?;
    let start_task = super::super::export_address(&windows.modules, b"KRNL386.EXE16", b"RetroWineStartTask")?;
    let image_path=super::super::guest_windows_path(windows.exec_path_str());
    const TASK_PATH: u32 = ENTER16 + 2048;
    let mut enter = Vec::new();
    emit_call(&mut enter, start_task, &[TASK_PATH, TASK_PATH + image_path.len() as u32]);
    enter.extend_from_slice(&[0x50, 0xb8]);
    enter.extend_from_slice(&abort.to_le_bytes());
    enter.extend_from_slice(&[0xff, 0xd0, 0x0f, 0x0b]);
    enter.resize(2048, 0);
    enter.extend_from_slice(&image_path);
    enter.push(0);
    map_code(machine, ENTER16, &enter)?;

    let attach_module = super::super::export_address(&windows.modules, b"NTDLL", b"RetroWineAttachModule")?;
    let initializers: Vec<_> = super::super::dll_initializers(&windows.modules, 1)?.into_iter()
        .map(|(base, _)| (base, attach_module)).collect();
    let attach = super::super::dll_startup_stub(machine, &initializers, ENTER16, abort)?;
    let mut bootstrap = Vec::new();
    let config = super::super::export_address(&windows.modules, b"KRNL386.EXE16", b"RetroWineConfigureSelectors")?;
    emit_call(&mut bootstrap, config, &[flat_ds, teb_selector as u32]);
    let import = super::super::export_address(&windows.modules, b"KRNL386.EXE16", b"RetroWineImportSelectors")?;
    emit_call(&mut bootstrap, import, &[windows.ldt.len() as u32]);
    regs.frame.rip = super::super::wine_startup::bootstrap(
        machine, &windows.modules, 1, attach, abort, bootstrap)? as u64;
    regs.frame.rsp = (super::super::STACK_TOP - 256) as u64;
    regs.fs = teb_selector as u64;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relays_select_normal_and_register_implementations_and_preserve_payloads() {
        let mut bytes = vec![0u8; 65];
        for at in [0, 32] { bytes[at] = 0x68; bytes[at + 5] = 0x9a; bytes[at + 1] = 42; }
        bytes[44..46].copy_from_slice(&0xcb66u16.to_le_bytes());
        assert_eq!(patch_calls(&mut bytes, 0x11223344, 0x55667788, 0x23), Ok(2));
        assert_eq!(&bytes[6..12], &[0x44,0x33,0x22,0x11,0x23,0]);
        assert_eq!(&bytes[38..44], &[0x88,0x77,0x66,0x55,0x23,0]);
        assert_eq!(bytes[1], 42);
        assert_eq!(bytes[33], 42);
        assert_eq!(patch_calls(&mut bytes[..31], 0, 0, 0), Err(-8));
    }
}
