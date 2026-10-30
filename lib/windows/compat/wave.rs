//! No Windows PCM stream backend is registered yet. Device enumeration and
//! failures must agree, and rejected operations never own guest buffers or
//! invoke callbacks. DOS sound remains independent of this interface.
const BAD_DEVICE: u32 = 2;
const INVALID_HANDLE: u32 = 5;
const NO_DRIVER: u32 = 6;
fn unavailable(device: u32) -> u32 {
    if device == u32::MAX {
        NO_DRIVER
    } else {
        BAD_DEVICE
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn waveOutGetNumDevs() -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn waveOutOpen(
    _out: u32,
    device: u32,
    _format: u32,
    _callback: u32,
    _instance: u32,
    _flags: u32,
) -> u32 {
    unavailable(device)
}
#[unsafe(no_mangle)]
pub extern "system" fn waveOutGetDevCapsA(device: u32, _out: u32, size: u32) -> u32 {
    if size == 0 { 0 } else { unavailable(device) }
}
#[unsafe(no_mangle)]
pub extern "system" fn waveOutClose(_handle: u32) -> u32 {
    INVALID_HANDLE
}
#[unsafe(no_mangle)]
pub extern "system" fn waveOutPrepareHeader(_handle: u32, _header: u32, _size: u32) -> u32 {
    INVALID_HANDLE
}
fn error_text(error: u32) -> Option<&'static [u8]> {
    Some(match error {
        0 => b"No error.",
        1 => b"Unspecified multimedia error.",
        2 => b"Invalid audio device identifier.",
        3 => b"The device is not enabled.",
        4 => b"The audio device is already allocated.",
        5 => b"Invalid audio device handle.",
        6 => b"No audio device driver is installed.",
        7 => b"Insufficient memory.",
        8 => b"Unsupported multimedia operation.",
        9 => b"Invalid multimedia error number.",
        10 => b"Invalid operation flag.",
        11 => b"Invalid parameter.",
        32 => b"Unsupported audio format.",
        33 => b"Audio buffers are still playing.",
        34 => b"The audio buffer is not prepared.",
        35 => b"The device requires synchronous playback.",
        _ => return None,
    })
}
unsafe fn write_error<T: Copy + From<u8>>(error: u32, out: *mut T, count: u32) -> u32 {
    if out.is_null() {
        return 11;
    }
    let Some(text) = error_text(error) else {
        if count != 0 {
            unsafe {
                out.write_unaligned(0.into());
            }
        }
        return 9;
    };
    if count != 0 {
        let n = text.len().min(count as usize - 1);
        for (i, &b) in text[..n].iter().enumerate() {
            unsafe {
                out.add(i).write_unaligned(b.into());
            }
        }
        unsafe {
            out.add(n).write_unaligned(0.into());
        }
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn waveOutGetErrorTextA(error: u32, out: *mut u8, count: u32) -> u32 {
    unsafe { write_error(error, out, count) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn waveOutGetErrorTextW(error: u32, out: *mut u16, count: u32) -> u32 {
    unsafe { write_error(error, out, count) }
}
