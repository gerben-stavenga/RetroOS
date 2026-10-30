//! Win16 MMIO layout and selector adapters; file/RIFF policy lives in WINMM.
use super::{far_pointer, huge_pointer, multimedia_export, pointer, string};
use crate::state;
type Info = [u32; 18];
unsafe fn get(h: u32) -> Result<Info, u32> {
    let entry = unsafe { multimedia_export(b"mmioGetInfo\0") };
    if entry == 0 {
        return Err(5);
    }
    let mut info = [0; 18];
    let result = unsafe {
        core::mem::transmute::<u32, unsafe extern "system" fn(u32, *mut Info, u32) -> u32>(entry)(
            h, &mut info, 0,
        )
    };
    if result == 0 { Ok(info) } else { Err(result) }
}
unsafe fn read_info(p: u32) -> Option<Info> {
    let p = unsafe { pointer(p, 66)? } as *const u8;
    let d = |n: usize| unsafe { p.add(n).cast::<u32>().read_unaligned() };
    let w = |n: usize| unsafe { p.add(n).cast::<u16>().read_unaligned() as u32 };
    let mut v = [0; 18];
    v[..3].copy_from_slice(&[d(0), d(4), d(8)]);
    v[3] = w(12);
    v[4] = w(14);
    for (i, x) in v.iter_mut().enumerate().take(17).skip(5) {
        *x = d(i * 4 - 4);
    }
    v[17] = w(64);
    Some(v)
}
unsafe fn write_info(p: u32, v: Info) -> Option<()> {
    let p = unsafe { pointer(p, 66)? } as *mut u8;
    let mut v = v;
    let base = if v[6] == 0 {
        0
    } else {
        unsafe { far_pointer(v[6])? }
    };
    for i in 7..=9 {
        v[i] = if v[i] == 0 {
            0
        } else {
            let delta = v[i].checked_sub(v[6])?;
            if delta > v[5] || (base & 0xffff).checked_add(delta)? > 65535 {
                return None;
            }
            base + delta
        };
    }
    v[6] = base;
    for (i, x) in v.iter().enumerate().take(3) {
        unsafe {
            p.add(i * 4).cast::<u32>().write_unaligned(*x);
        }
    }
    unsafe {
        p.add(12).cast::<u16>().write_unaligned(v[3] as u16);
        p.add(14).cast::<u16>().write_unaligned(v[4] as u16);
    }
    for (i, x) in v.iter().enumerate().take(17).skip(5) {
        unsafe {
            p.add(i * 4 - 4).cast::<u32>().write_unaligned(*x);
        }
    }
    unsafe {
        p.add(64).cast::<u16>().write_unaligned(v[17] as u16);
    }
    Some(())
}
unsafe fn update_info(h: u32, p: u32) -> Result<Info, u32> {
    let mut current = unsafe { get(h)? };
    let v = unsafe { read_info(p) }.ok_or(11u32)?;
    let base = if current[6] == 0 {
        0
    } else {
        unsafe { far_pointer(current[6]) }.ok_or(11u32)?
    };
    if v[6] != base || v[5] != current[5] {
        return Err(11);
    }
    for i in 7..=9 {
        if v[i] == 0 && base == 0 {
            current[i] = 0;
            continue;
        }
        let delta = v[i]
            .checked_sub(base)
            .filter(|n| *n <= current[5] && (base & 0xffff) + n <= 65535)
            .ok_or(11u32)?;
        current[i] = current[6] + delta;
    }
    current[0] = v[0];
    Ok(current)
}
pub(super) unsafe fn dispatch(o: u32, a: u32) -> Option<u32> {
    unsafe {
        let w = |n: u32| ((a + n) as *const u16).read_unaligned() as u32;
        let d = |n: u32| ((a + n) as *const u32).read_unaligned();
        Some(match o {
            4210 => {
                let owner = w(0) as u16;
                let flags = d(2);
                let info16 = d(6);
                let mut v = if info16 == 0 {
                    [0; 18]
                } else {
                    read_info(info16)?
                };
                let cch = if v[5] == 0 && flags & 0x10000 != 0 {
                    8192
                } else {
                    v[5]
                };
                let buffer = if v[6] != 0 {
                    v[6]
                } else {
                    u32::from(owner) << 16
                };
                let valid = cch <= 65535
                    && (buffer & 0xffff)
                        .checked_add(cch)
                        .is_some_and(|n| n <= 65535);
                let mut handle = 0;
                if !valid || (cch != 0 && buffer == 0) {
                    v[3] = 258;
                } else {
                    v[5] = cch;
                    v[6] = if cch == 0 {
                        0
                    } else {
                        pointer(buffer, cch as usize)?
                    };
                    let entry = multimedia_export(b"mmioOpenA\0");
                    if entry == 0 {
                        v[3] = 259;
                    } else {
                        let name = if d(10) == 0 { 0 } else { string(d(10))? };
                        handle = core::mem::transmute::<
                            u32,
                            unsafe extern "system" fn(u32, *mut Info, u32) -> u32,
                        >(entry)(name, &mut v, flags & !0x10000);
                    }
                }
                if handle != 0 {
                    state::with(|s| s.mmio_buffers.push((handle, owner)));
                }
                if info16 != 0 {
                    let p = pointer(info16, 66)? as *mut u8;
                    p.add(12).cast::<u16>().write_unaligned(v[3] as u16);
                    p.add(64).cast::<u16>().write_unaligned(handle as u16);
                }
                handle
            }
            4211 => {
                let entry = multimedia_export(b"mmioClose\0");
                if entry == 0 {
                    return Some(5);
                }
                let h = w(2);
                let result = core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32) -> u32>(
                    entry,
                )(h, w(0));
                if result != 0 {
                    result
                } else {
                    state::with(|s| {
                        if let Some(i) = s.mmio_buffers.iter().position(|v| v.0 == h) {
                            u32::from(s.mmio_buffers.remove(i).1) << 16
                        } else {
                            0
                        }
                    })
                }
            }
            4212 | 4213 => {
                let n = d(0);
                if n > i32::MAX as u32 {
                    return Some(u32::MAX);
                }
                let entry = multimedia_export(if o == 4212 {
                    b"mmioRead\0"
                } else {
                    b"mmioWrite\0"
                });
                let Some(p) = (if n == 0 {
                    Some(0)
                } else {
                    huge_pointer(d(4), n as usize)
                }) else {
                    return Some(u32::MAX);
                };
                if entry == 0 {
                    u32::MAX
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32, u32) -> u32>(
                        entry,
                    )(w(8), p, n)
                }
            }
            4214 => {
                let entry = multimedia_export(b"mmioSeek\0");
                if entry == 0 {
                    u32::MAX
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32, u32) -> u32>(
                        entry,
                    )(w(6), d(2), w(0))
                }
            }
            4215 => {
                if w(0) != 0 {
                    11
                } else {
                    match get(w(6)) {
                        Err(e) => e,
                        Ok(v) => {
                            if write_info(d(2), v).is_some() {
                                0
                            } else {
                                11
                            }
                        }
                    }
                }
            }
            4216 | 4219 => {
                let h = w(6);
                let p = d(2);
                let mut info = if p == 0 && o == 4219 {
                    [0; 18]
                } else {
                    match update_info(h, p) {
                        Ok(v) => v,
                        Err(e) => return Some(e),
                    }
                };
                let entry = multimedia_export(if o == 4216 {
                    b"mmioSetInfo\0"
                } else {
                    b"mmioAdvance\0"
                });
                if entry == 0 {
                    5
                } else {
                    let result = core::mem::transmute::<
                        u32,
                        unsafe extern "system" fn(u32, *mut Info, u32) -> u32,
                    >(entry)(
                        h,
                        if p == 0 {
                            core::ptr::null_mut()
                        } else {
                            &mut info
                        },
                        w(0),
                    );
                    if result == 0 && o == 4219 && p != 0 && write_info(p, info).is_none() {
                        11
                    } else {
                        result
                    }
                }
            }
            4218 => {
                let entry = multimedia_export(b"mmioFlush\0");
                if entry == 0 {
                    5
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32) -> u32>(entry)(
                        w(2),
                        w(0),
                    )
                }
            }
            4220 => {
                let entry = multimedia_export(b"mmioStringToFOURCCA\0");
                if entry == 0 {
                    0
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32) -> u32>(entry)(
                        if d(2) == 0 { 0 } else { string(d(2))? },
                        w(0),
                    )
                }
            }
            4223 => {
                let entry = multimedia_export(b"mmioDescend\0");
                let Some(chunk) = pointer(d(6), 20) else {
                    return Some(11);
                };
                let parent = if d(2) == 0 {
                    0
                } else {
                    match pointer(d(2), 20) {
                        Some(p) => p,
                        None => return Some(11),
                    }
                };
                if entry == 0 {
                    5
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32, u32, u32) -> u32>(
                        entry,
                    )(w(10), chunk, parent, w(0))
                }
            }
            4224 | 4225 => {
                let entry = multimedia_export(if o == 4224 {
                    b"mmioAscend\0"
                } else {
                    b"mmioCreateChunk\0"
                });
                let Some(chunk) = pointer(d(2), 20) else {
                    return Some(11);
                };
                if entry == 0 {
                    5
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32, u32) -> u32>(
                        entry,
                    )(w(6), chunk, w(0))
                }
            }
            _ => return None,
        })
    }
}
