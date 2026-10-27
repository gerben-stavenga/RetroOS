//! Message boxes are ordinary shared dialogs, including their modal message loop.
use crate::{dialog, input, text, window};
use alloc::{vec, vec::Vec};
fn word(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn long(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn string(out: &mut Vec<u8>, s: &[u16]) {
    for &c in s {
        word(out, c);
    }
    word(out, 0);
}
fn item(
    out: &mut Vec<u8>,
    style: u32,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    id: u16,
    class: u16,
    title: &[u16],
) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
    long(out, style);
    long(out, 0);
    for v in [x, y, w, h, id, 0xffff, class] {
        word(out, v);
    }
    string(out, title);
    word(out, 0);
}
fn lines(text: &[u16]) -> Vec<Vec<u16>> {
    let mut result = Vec::new();
    for paragraph in text.split(|&c| c == 10) {
        let mut rest = paragraph.strip_suffix(&[13]).unwrap_or(paragraph);
        if rest.is_empty() {
            result.push(Vec::new());
        }
        while !rest.is_empty() {
            let mut end = rest.len().min(54);
            if end < rest.len() {
                if let Some(space) = rest[..end].iter().rposition(|&c| c == 32) {
                    if space > 0 {
                        end = space;
                    }
                }
            }
            result.push(rest[..end].to_vec());
            rest = &rest[end..];
            while rest.first() == Some(&32) {
                rest = &rest[1..];
            }
        }
    }
    result
}
unsafe extern "system" fn procedure(hwnd: u32, msg: u32, wp: u32, lp: u32) -> i32 {
    match msg {
        0x110 => {
            unsafe {
                window::SetWindowLongA(hwnd, -21, lp >> 16);
                crate::SendMessageW(hwnd, 0x401, lp & 0xffff, 0);
                input::SetFocus(window::GetDlgItem(hwnd, (lp & 0xffff) as i32));
            }
            0 // Focus was set explicitly.
        }
        0x111 => {
            let id = wp & 0xffff;
            if window::GetDlgItem(hwnd, id as i32) != 0 {
                dialog::EndDialog(hwnd, id as i32);
            }
            1
        }
        0x10 => {
            let cancel = unsafe { window::GetWindowLongA(hwnd, -21) };
            if cancel != 0 {
                dialog::EndDialog(hwnd, cancel as i32);
            }
            1
        }
        _ => 0,
    }
}
unsafe fn show(owner: u32, body: u32, caption: u32, flags: u32, wide: bool) -> i32 {
    let buttons: &[(u16, &str)] = match flags & 15 {
        0 => &[(1, "OK")],
        1 => &[(1, "OK"), (2, "Cancel")],
        2 => &[(3, "Abort"), (4, "Retry"), (5, "Ignore")],
        3 => &[(6, "Yes"), (7, "No"), (2, "Cancel")],
        4 => &[(6, "Yes"), (7, "No")],
        5 => &[(4, "Retry"), (2, "Cancel")],
        6 => &[(2, "Cancel"), (10, "Try Again"), (11, "Continue")],
        _ => {
            crate::state::error(87);
            return 0;
        }
    };
    let default = ((flags >> 8) & 3).min(buttons.len() as u32 - 1) as usize;
    let cancel = if buttons.iter().any(|b| b.0 == 2) {
        2
    } else if buttons.len() == 1 {
        1
    } else {
        0
    };
    let body = unsafe { text::read(body, wide) };
    let caption = if caption == 0 {
        "Error".encode_utf16().collect()
    } else {
        unsafe { text::read(caption, wide) }
    };
    let lines = lines(&body);
    let width = (lines.iter().map(|l| l.len()).max().unwrap_or(0) * 4 + 20)
        .max(buttons.len() * 54 + 16)
        .min(236) as u16;
    let button_y = (lines.len() * 9 + 20) as u16;
    let height = button_y + 24;
    let mut template = vec![];
    long(&mut template, 0x80c8_0000);
    long(&mut template, 0);
    for v in [
        (lines.len() + buttons.len()) as u16,
        20,
        20,
        width,
        height,
        0,
        0,
    ] {
        word(&mut template, v);
    }
    string(&mut template, &caption);
    for (i, line) in lines.iter().enumerate() {
        item(
            &mut template,
            0x5000_0080,
            10,
            8 + i as u16 * 9,
            width - 20,
            9,
            0xffff,
            0x82,
            line,
        );
    }
    let start = (width - buttons.len() as u16 * 54 + 4) / 2;
    for (i, &(id, label)) in buttons.iter().enumerate() {
        item(
            &mut template,
            0x5001_0000 | u32::from(i == default),
            start + i as u16 * 54,
            button_y,
            50,
            14,
            id,
            0x80,
            &label.encode_utf16().collect::<Vec<_>>(),
        );
    }
    let focus = input::GetFocus();
    let enable = owner != 0 && window::IsWindowEnabled(owner) != 0;
    if enable {
        window::EnableWindow(owner, 0);
    }
    let result = unsafe {
        dialog::DialogBoxIndirectParamW(
            0,
            template.as_ptr() as u32,
            owner,
            procedure as *const () as u32,
            u32::from(buttons[default].0) | (cancel << 16),
        )
    };
    if enable && window::IsWindow(owner) != 0 {
        window::EnableWindow(owner, 1);
    }
    if window::IsWindow(focus) != 0 {
        unsafe {
            input::SetFocus(focus);
        }
    }
    if result < 0 { 0 } else { result }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn MessageBoxA(owner: u32, body: u32, caption: u32, flags: u32) -> i32 {
    unsafe { show(owner, body, caption, flags, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn MessageBoxW(owner: u32, body: u32, caption: u32, flags: u32) -> i32 {
    unsafe { show(owner, body, caption, flags, true) }
}
