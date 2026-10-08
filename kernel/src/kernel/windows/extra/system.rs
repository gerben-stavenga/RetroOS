//! Additional console APIs and explicit failure results for optional services.
use super::*;

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    regs: &mut Regs,
    name: &[u8],
) -> u32 {
    let args: [u32; 12] = core::array::from_fn(|n| arg(machine, regs, n));
    let a = |n: usize| args[n];
    match name {
        b"ChangeDisplaySettingsA" => u32::MAX, // DISP_CHANGE_FAILED
        b"EnumDisplaySettingsA" => fail(state,120,0),
        b"OpenFileMappingA" => {
            let name = c_string(machine, a(2)).unwrap_or_default();
            if let Some(mapping) = state
                .mappings
                .iter()
                .find(|m| !name.is_empty() && m.name == name)
            {
                mapping.handle
            } else {
                fail(state, ERROR_FILE_NOT_FOUND, 0)
            }
        }
        b"CreateFileMappingA" => {
            if a(0) != INVALID_HANDLE_VALUE {
                return fail(state, 120, 0);
            }
            let name = if a(5) != 0 {
                c_string(machine, a(5)).unwrap_or_default()
            } else {
                Vec::new()
            };
            if let Some(mapping) = state
                .mappings
                .iter()
                .find(|m| !name.is_empty() && m.name == name)
            {
                state.last_error = 183;
                return mapping.handle;
            }
            if a(3) != 0 || a(4) == 0 || a(4) > 16 * 1024 * 1024 || a(2) != 4 {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            }
            let size = a(4).next_multiple_of(4096);
            let allocation = heap_alloc(machine, state, 8, size + 4095);
            if allocation == 0 {
                return fail(state, 8, 0);
            }
            let address = allocation.next_multiple_of(4096);
            let handle = state.next_object;
            state.next_object += 1;
            state.mappings.push(Mapping {
                handle,
                name,
                address,
                size,
            });
            state.last_error = 0;
            handle
        }
        b"MapViewOfFile" => {
            if a(2) != 0 {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            }
            if let Some(mapping) = state.mappings.iter().find(|m| m.handle == a(0)) {
                let offset = a(3);
                if offset < mapping.size && (a(4) == 0 || a(4) <= mapping.size - offset) {
                    mapping.address + offset
                } else {
                    fail(state, ERROR_INVALID_PARAMETER, 0)
                }
            } else {
                fail(state, ERROR_INVALID_HANDLE, 0)
            }
        }
        b"UnmapViewOfFile" => {
            if state
                .mappings
                .iter()
                .any(|m| a(0) >= m.address && a(0) < m.address + m.size)
            {
                1
            } else {
                fail(state, ERROR_INVALID_PARAMETER, 0)
            }
        }
        b"VirtualProtect" => {
            if a(3) == 0 {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            }
            match super::super::change_protection(machine, state, a(0), a(1), a(2)) {
                Ok(old) => {
                    machine.write::<u32>(a(3) as usize, old);
                    1
                }
                Err(error) => fail(state, error, 0),
            }
        }
        b"RegisterWindowMessageA" => {
            let Ok(name) = c_string(machine, a(0)) else {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            };
            if let Some((_, id)) = state.registered_messages.iter().find(|(n, _)| *n == name) {
                return *id;
            }
            let id = 0xc000 + state.registered_messages.len() as u32;
            state.registered_messages.push((name, id));
            id
        }
        b"RegisterClassExA" => {
            let wc = a(0) as usize;
            let Ok(name) = c_string(machine, machine.read::<u32>(wc + 40)) else {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            };
            let wndproc = machine.read::<u32>(wc + 8);
            let background = machine.read::<u32>(wc + 32);
            state.classes.push(super::super::WindowClass {
                name,
                wndproc,
                background,
            });
            state.classes.len() as u32
        }
        b"CreateWindowExA" => {
            super::super::dispatch(machine, kt, state, regs, super::super::Api::CreateWindowExA)
        }
        b"GetMessageA" | b"PeekMessageA" => {
            let id = machine.read::<u32>((super::super::TEB_BASE + 0x24) as usize);
            let found = state
                .thread_messages
                .iter()
                .position(|(owner, _)| *owner == id);
            let message = found
                .map(|i| state.thread_messages[i].1)
                .or_else(|| state.messages.first().copied());
            let Some(message) = message else {
                if name == b"GetMessageA" {
                    state.console.hold = true;
                }
                return 0;
            };
            super::super::write_message(machine, a(0) as usize, message);
            if name == b"GetMessageA" || a(4) & 1 != 0 {
                if let Some(i) = found {
                    state.thread_messages.remove(i);
                } else {
                    state.messages.remove(0);
                }
            }
            u32::from(message.message != 0x12)
        }
        b"PostThreadMessageA" => {
            state.thread_messages.push((
                a(0),
                super::super::Message {
                    hwnd: 0,
                    message: a(1),
                    wparam: a(2),
                    lparam: a(3),
                },
            ));
            1
        }
        b"PostMessageA" => {
            super::super::dispatch(machine, kt, state, regs, super::super::Api::PostMessageW)
        }
        b"DispatchMessageA" | b"DefWindowProcA" => 0,
        b"IsWindow" | b"IsWindowVisible" => u32::from(state.windows.iter().any(|w| w.hwnd == a(0))),
        b"LoadStringA" => {
            if a(3) as i32 <= 0 || a(2) == 0 {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            }
            let Some(module) = state.modules.iter().find(|m| m.base == a(0)) else {
                return fail(state, ERROR_INVALID_HANDLE, 0);
            };
            let text =
                super::super::pe::Image::parse(&module.data).and_then(|p| p.string_resource(a(1)));
            let Ok(text) = text else {
                machine.write::<u8>(a(2) as usize, 0);
                return fail(state, 1814, 0);
            };
            let text = crate::kernel::text::from_utf16(&text, false).unwrap();
            let bytes = encoding::ansi().encode(&text, b'?').0;
            let n = bytes.len().min(a(3) as usize - 1);
            machine.copy_to(a(2) as usize, &bytes[..n]);
            machine.write::<u8>(a(2) as usize + n, 0);
            n as u32
        }
        b"AllocConsole" => {
            open_console(state);
            1
        }
        b"GetConsoleCP" => state.console.input_cp,
        b"GetConsoleOutputCP" => state.console.output_cp,
        b"SetConsoleCP" | b"SetConsoleOutputCP" => {
            if encoding::page(a(0)).is_none() { return fail(state, ERROR_INVALID_PARAMETER, 0); }
            if name == b"SetConsoleCP" { state.console.input_cp = a(0); }
            else { state.console.output_cp = a(0); }
            1
        },
        b"GetThreadLocale" => lib::locale::current().lcid,
        b"AreFileApisANSI" => u32::from(!state.file_oem),
        b"SetFileApisToANSI" => { state.file_oem = false; 0 },
        b"SetConsoleIcon"
        | b"SetPriorityClass"
        | b"SetProcessShutdownParameters" => 1,
        b"SetFileApisToOEM" => { state.file_oem = true; 0 },
        b"FlushConsoleInputBuffer" => {
            state.console.input.clear();
            1
        }
        b"GetLargestConsoleWindowSize" => {
            u32::from(state.console.cols) | (u32::from(state.console.rows) << 16)
        }
        b"GetConsoleCursorInfo" => {
            machine.write::<u32>(a(1) as usize, 25);
            machine.write::<u32>(a(1) as usize + 4, 1);
            1
        }
        b"SetConsoleCursorInfo" => 1,
        b"GlobalAlloc" => heap_alloc(machine, state, if a(0) & 0x40 != 0 { 8 } else { 0 }, a(1)),
        b"GlobalLock" => a(0),
        b"GlobalUnlock" => {
            state.last_error = 0;
            0
        }
        b"GlobalSize" => state
            .blocks
            .iter()
            .find(|b| b.used && b.addr == a(0))
            .map_or(0, |b| b.size),
        b"GlobalMemoryStatus" => {
            let out = a(0) as usize;
            machine.zero(out, 32);
            machine.write::<u32>(out, 32);
            for (off, value) in [
                (8, 128 * 1024 * 1024),
                (12, 64 * 1024 * 1024),
                (16, 128 * 1024 * 1024),
                (20, 64 * 1024 * 1024),
                (24, 0x7fff0000),
                (28, 0x40000000),
            ] {
                machine.write::<u32>(out + off, value);
            }
            0
        }
        b"QueryPerformanceCounter" => {
            machine.write::<u64>(a(0) as usize, machine.now());
            1
        }
        b"QueryPerformanceFrequency" => {
            machine.write::<u64>(a(0) as usize, 1_000_000_000);
            1
        }
        b"GetSystemTimeAsFileTime" => {
            machine.write::<u64>(
                a(0) as usize,
                filetime(crate::kernel::clock::rtc_unix_timestamp().unwrap_or(0)),
            );
            0
        }
        b"GetFileSizeEx" => match crate::kernel::vfs::fd_info(a(0) as i32, &kt.fds) {
            Some((stat, _)) => {
                machine.write::<u64>(a(1) as usize, u64::from(stat.size));
                1
            }
            None => fail(state, ERROR_INVALID_HANDLE, 0),
        },
        b"GetFileTime" => match crate::kernel::vfs::fd_info(a(0) as i32, &kt.fds) {
            Some((_, mtime)) => {
                for n in 1..4 {
                    if a(n) != 0 {
                        machine.write::<u64>(a(n) as usize, filetime(mtime));
                    }
                }
                1
            }
            None => fail(state, ERROR_INVALID_HANDLE, 0),
        },
        b"FileTimeToDosDateTime" => {
            let time =
                system_time(unix_from_filetime(machine.read::<u64>(a(0) as usize)).unwrap_or(-1));
            if !(1980..=2107).contains(&time[0]) {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            }
            machine.write::<u16>(
                a(1) as usize,
                ((time[0] - 1980) << 9) | (time[1] << 5) | time[3],
            );
            machine.write::<u16>(
                a(2) as usize,
                (time[4] << 11) | (time[5] << 5) | (time[6] / 2),
            );
            1
        }
        b"DosDateTimeToFileTime" => {
            let date = a(0) as u16;
            let time = a(1) as u16;
            let fields = [
                1980 + (date >> 9),
                (date >> 5) & 15,
                0,
                date & 31,
                time >> 11,
                (time >> 5) & 63,
                (time & 31) * 2,
                0,
            ];
            let Some(value) = filetime_from_system_time(fields) else {
                return fail(state, ERROR_INVALID_PARAMETER, 0);
            };
            machine.write::<u64>(a(2) as usize, value);
            1
        }
        b"GetShortPathNameA" => match c_string(machine, a(0)) {
            Ok(path) => {
                if a(2) as usize <= path.len() {
                    (path.len() + 1) as u32
                } else {
                    copy_ascii(machine, a(1) as usize, a(2) as usize, &path);
                    path.len() as u32
                }
            }
            Err(e) => fail(state, e, 0),
        },
        b"WaitForSingleObjectEx" => 0,
        b"FindFirstChangeNotificationA" => fail(state, 120, INVALID_HANDLE_VALUE),
        b"GetIpNetTable" => 50,
        b"SHGetFolderPathA" => 0x80004001,
        b"inet_addr" => u32::MAX,
        b"CoInitialize" | b"OleInitialize" => 0,
        b"CoCreateInstance" => {
            if a(4) != 0 {
                machine.write::<u32>(a(4) as usize, 0);
            }
            0x80040154
        }
        b"CoGetMalloc" | b"SHGetSpecialFolderLocation" => {
            if a(1) != 0 {
                machine.write::<u32>(a(1) as usize, 0);
            }
            0x80004001
        }
        b"SHGetDesktopFolder" => {
            if a(0) != 0 {
                machine.write::<u32>(a(0) as usize, 0);
            }
            0x80004001
        }
        b"OleUninitialize" | b"GdiplusShutdown" => 0,
        b"GdiplusStartup"
        | b"GdipCreateBitmapFromHBITMAP"
        | b"GdipGetImageEncodersSize"
        | b"GdipGetImageEncoders"
        | b"GdipSaveImageToFile"
        | b"GdipDisposeImage" => 6,
        b"NtQueryObject" | b"NtQuerySystemInformation" | b"NtQueryInformationFile" => 0xc0000002,
        b"WNetGetUniversalNameA"
        | b"WNetGetConnectionA"
        | b"WNetOpenEnumA"
        | b"WNetEnumResourceA"
        | b"WNetCloseEnum"
        | b"WNetCancelConnection2A"
        | b"WNetAddConnection2A" => 1222,
        b"RegCreateKeyExA" | b"RegOpenKeyA" | b"RegOpenKeyExA" | b"RegQueryValueExA"
        | b"RegSetValueExA" => 2,
        b"WSAStartup" => 10091,
        b"WSACleanup" => 0,
        b"WSAGetLastError" => state.last_error,
        b"WSASetLastError" => {
            state.last_error = a(0);
            0
        }
        b"htons" | b"ntohs" => u32::from((a(0) as u16).swap_bytes()),
        b"socket" | b"accept" | b"connect" | b"bind" | b"listen" | b"send" | b"recv"
        | b"select" | b"shutdown" | b"closesocket" | b"setsockopt" | b"getsockname" => {
            fail(state, 10050, u32::MAX)
        }
        b"ShellExecuteA" => fail(state, 120, 31),
        b"SHFileOperationA" => 120,
        b"timeSetEvent" => 0,
        b"timeKillEvent" | b"mciSendStringA" => 1,
        b"GetDesktopWindow" | b"GetForegroundWindow" => state.console.hwnd,
        b"GetKeyboardState" => {
            machine.copy_to(a(0) as usize, &state.console.keys);
            1
        }
        b"GetCursorPos" => {
            machine.zero(a(0) as usize, 8);
            1
        }
        b"GetAsyncKeyState" | b"GetKeyState" => {
            if a(0) < 256 {
                let bits = state.console.keys[a(0) as usize];
                let down = if bits & 0x80 != 0 { 0xffff8000 } else { 0 };
                down | if name == b"GetKeyState" { u32::from(bits & 1) } else { 0 }
            } else { 0 }
        }
        b"GetMenuItemCount" => u32::MAX,
        b"MessageBoxA" => {
            if let Ok(text) = c_string(machine, a(1)) {
                crate::compact_println!(
                    "Windows: {}",
                    core::str::from_utf8(&text).unwrap_or("message")
                );
            }
            1
        }
        b"CharUpperBuffA" | b"CharLowerBuffA" => {
            for i in 0..a(1) as usize {
                let at = a(0) as usize + i;
                let ch = machine.read::<u8>(at);
                machine.write::<u8>(
                    at,
                    if name == b"CharUpperBuffA" {
                        lib::codepage::encoding_page(lib::locale::current().ansi).unwrap().uppercase(ch)
                    } else {
                        { let page = lib::codepage::encoding_page(lib::locale::current().ansi).unwrap();
                        let mut lower = page.decode(ch).to_lowercase();
                        let value = lower.next().and_then(|c| page.encode_exact(c)).unwrap_or(ch);
                        if lower.next().is_none() { value } else { ch }
                    }
                    },
                );
            }
            a(1)
        }
        b"OemToCharBuffA" | b"CharToOemBuffA" | b"OemToCharA" | b"CharToOemA" => {
            let data = if name.ends_with(b"BuffA") {
                (0..a(2) as usize).map(|i| machine.read::<u8>(a(0) as usize + i)).collect()
            } else {
                let Ok(mut data) = super::super::raw_string(machine, a(0)) else { return fail(state, ERROR_INVALID_PARAMETER, 0); };
                data.push(0); data
            };
            let (from, to) = if name.starts_with(b"OemToChar") {
                (crate::kernel::text::Encoding::oem(), encoding::ansi())
            } else { (encoding::ansi(), crate::kernel::text::Encoding::oem()) };
            let text = from.decode(&data, false).unwrap();
            machine.copy_to(a(1) as usize, &to.encode(&text, b'?').0);
            1
        }
        b"strcpy" => {
            if let Ok(mut data) = super::super::raw_string(machine, a(1)) {
                data.push(0); machine.copy_to(a(0) as usize, &data);
            }
            a(0)
        }
        b"malloc" => heap_alloc(machine, state, 0, a(0)),
        b"calloc" => heap_alloc(machine, state, 8, a(0).saturating_mul(a(1))),
        b"free" => {
            heap_free(state, a(0));
            0
        }
        b"strlen" => super::super::raw_string(machine, a(0)).map_or(0, |s| s.len() as u32),
        b"_lock" | b"_unlock" | b"_initterm" => 0,
        _ => fail(state, 120, 0),
    }
}

fn filetime_from_system_time(t: [u16; 8]) -> Option<u64> {
    let (year, month, day) = (i64::from(t[0]), i64::from(t[1]), i64::from(t[3]));
    if !(1601..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || t[4] > 23
        || t[5] > 59
        || t[6] > 59
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month as usize - 1]
        + i64::from(month == 2 && leap);
    if day > max_day {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let days =
        era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5 + day - 1 - 719468;
    let unix = days * 86400 + i64::from(t[4]) * 3600 + i64::from(t[5]) * 60 + i64::from(t[6]);
    Some((unix + FILETIME_EPOCH as i64) as u64 * 10_000_000 + u64::from(t[7]) * 10_000)
}
