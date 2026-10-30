//! MCI queries when no playback driver is installed. Keep this policy shared
//! by Win16 and Win32; never fabricate an open device or successful playback.
const INVALID_DEVICE: u32 = 257;
const CANNOT_LOAD_DRIVER: u32 = 266;
const NULL_PARAMETER_BLOCK: u32 = 297;
const ALL_DEVICES: u32 = u32::MAX;

unsafe fn is_all<T: Copy + Into<u32>>(name: *const T) -> bool {
    if name.is_null() {
        return false;
    }
    for (i, expected) in [b'a', b'l', b'l', 0].iter().enumerate() {
        let c: u32 = unsafe { name.add(i).read_unaligned() }.into();
        let c = if (65..=90).contains(&c) { c + 32 } else { c };
        if c != u32::from(*expected) {
            return false;
        }
    }
    true
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mciGetDeviceIDA(name: *const u8) -> u32 {
    if unsafe { is_all(name) } {
        ALL_DEVICES
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mciGetDeviceIDW(name: *const u16) -> u32 {
    if unsafe { is_all(name) } {
        ALL_DEVICES
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn mciSetDriverData(_device: u32, _data: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn mciGetDriverData(_device: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn mciSetYieldProc(_device: u32, _callback: u32, _data: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn mciGetYieldProc(_device: u32, _data: *mut u32) -> u32 {
    0
}

// No parameter block is dereferenced until a driver exists. The Win16 adapter
// can therefore pass its validated block without interpreting driver-specific
// layouts. Opening a driver must introduce the corresponding ABI conversion.
#[unsafe(no_mangle)]
pub extern "system" fn mciSendCommandA(
    device: u32,
    command: u32,
    _flags: u32,
    parameters: u32,
) -> u32 {
    match command {
        0x803 if parameters == 0 => NULL_PARAMETER_BLOCK, // MCI_OPEN
        0x803 => CANNOT_LOAD_DRIVER,
        0x804 if device == ALL_DEVICES => 0, // closing an empty set
        _ => INVALID_DEVICE,
    }
}
fn error_text(error: u32) -> Option<&'static [u8]> {
    Some(match error {
        0 => b"No error.",
        257 => b"Invalid MCI device identifier.",
        259 => b"Unrecognized command parameter.",
        261 => b"Unrecognized MCI command.",
        262 => b"The media device reported an error.",
        263 => b"The named MCI device is not open.",
        264 => b"Insufficient memory.",
        265 => b"The device alias is already in use.",
        266 => b"The requested MCI driver could not be loaded.",
        267 => b"No MCI command was supplied.",
        268 => b"The output buffer is too small.",
        269 => b"A string parameter is required.",
        270 => b"Invalid integer parameter.",
        273 => b"A required parameter is missing.",
        274 => b"The MCI driver does not support this operation.",
        275 => b"The media file was not found.",
        276 => b"The media device is not ready.",
        277 => b"MCI initialization failed.",
        289 => b"The supplied flags are incompatible.",
        292 => b"A device name is required.",
        297 => b"A parameter block is required.",
        _ => return None,
    })
}
unsafe fn write_error<T: Copy + From<u8>>(error: u32, out: *mut T, count: u32) -> i32 {
    if out.is_null() || count == 0 {
        return 0;
    }
    let text = error_text(error);
    let bytes = text.unwrap_or(b"");
    let n = bytes.len().min(count as usize - 1);
    for (i, &b) in bytes[..n].iter().enumerate() {
        unsafe {
            out.add(i).write_unaligned(b.into());
        }
    }
    unsafe {
        out.add(n).write_unaligned(0.into());
    }
    i32::from(text.is_some())
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mciGetErrorStringA(error: u32, out: *mut u8, count: u32) -> i32 {
    unsafe { write_error(error, out, count) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mciGetErrorStringW(error: u32, out: *mut u16, count: u32) -> i32 {
    unsafe { write_error(error, out, count) }
}
