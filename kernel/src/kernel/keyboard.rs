//! Foreground keyboard state and shared Unicode layout translation.
//! Raw Set-1 scancodes remain available to DOS programs that own IRQ1.
static mut STATE: lib::keyboard::State = lib::keyboard::State::new();
static mut EVENT: lib::keyboard::Event = lib::keyboard::Event {
    scan: 0, extended: false, pressed: false, repeat: false,
    text: ['\0';2], length: 0, dead: false,
};

pub(crate) fn key_down(key: u8) -> bool {
    unsafe { (&*core::ptr::addr_of!(STATE)).down(key,false) || (&*core::ptr::addr_of!(STATE)).down(key,true) }
}
pub fn update_key_state(scancode: u8) -> bool {
    unsafe {
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        EVENT = state.feed(lib::keyboard::current(),scancode);
        EVENT.pressed
    }
}
/// Keep lock/dead-key state with the console that owns this input stream.
pub fn update_console(state: &mut lib::keyboard::State, scancode: u8) -> bool {
    let event = state.feed(lib::keyboard::current(),scancode);
    unsafe { STATE = *state; EVENT = event; }
    event.pressed
}

pub fn event() -> lib::keyboard::Event { unsafe { EVENT } }
pub fn control_state() -> u32 {
    unsafe {
        let state = &*core::ptr::addr_of!(STATE);
        u32::from(state.down(0x38,true)) | (u32::from(state.down(0x38,false)) << 1)
            | (u32::from(state.down(0x1d,true)) << 2) | (u32::from(state.down(0x1d,false)) << 3)
            | (u32::from(state.shift()) << 4) | (u32::from(state.num) << 5)
            | (u32::from(state.scroll) << 6) | (u32::from(state.caps) << 7)
    }
}
pub fn oem_character(character: char) -> u8 {
    lib::codepage::current_codepage().encode_exact(character).unwrap_or(b'?')
}
pub fn ascii_to_scancodes(byte: u8) -> ([u8;16],usize) {
    lib::keyboard::sequence(lib::keyboard::current(),char::from(byte))
}

#[cfg(test)]
mod tests {
    use lib::keyboard::{Layout, State, Symbol, sequence, symbol};
    use Symbol::{Character as C, Dead as D};

    #[test]
    fn italian_iso_accents_and_altgr() {
        assert_eq!(symbol(Layout::It,0x1a,false,false,false,false),C('è'));
        assert_eq!(symbol(Layout::It,0x1a,true,false,false,false),C('é'));
        assert_eq!(symbol(Layout::It,0x1a,false,true,false,false),C('['));
        assert_eq!(symbol(Layout::It,0x1a,true,true,false,false),C('{'));
        assert_eq!(symbol(Layout::It,0x27,false,true,false,false),C('@'));
        assert_eq!(symbol(Layout::It,0x29,false,false,false,false),C('\\'));
        assert_eq!(symbol(Layout::It,0x56,true,false,false,false),C('>'));
    }
    #[test]
    fn german_caps_and_ctrl_preserve_shortcuts() {
        assert_eq!(symbol(Layout::De,0x15,false,false,false,false),C('z'));
        assert_eq!(symbol(Layout::De,0x1a,false,false,true,false),C('Ü'));
        assert_eq!(symbol(Layout::De,0x1a,true,false,true,false),C('ü'));
        assert_eq!(symbol(Layout::De,0x03,false,false,true,false),C('2'));
        assert_eq!(symbol(Layout::De,0x15,false,false,false,true),C('\x1a'));
        assert_eq!(symbol(Layout::De,0x29,false,false,false,false),D('^'));
    }
    #[test]
    fn dead_keys_compose_or_preserve_both_characters() {
        let mut state = State::new();
        assert!(state.feed(Layout::De,0x0d).dead);
        state.feed(Layout::De,0x8d);
        assert_eq!(state.feed(Layout::De,0x12).characters(), &['é']);
        state.feed(Layout::De,0x92);
        state.feed(Layout::De,0x29); state.feed(Layout::De,0xa9);
        assert_eq!(state.feed(Layout::De,0x2d).characters(), &['^','x']);
        state.feed(Layout::De,0x29); state.feed(Layout::De,0xa9);
        assert_eq!(state.feed(Layout::De,0x39).characters(), &['^']);
    }
    #[test]
    fn right_alt_is_distinct_and_caps_toggles_once_per_press() {
        let mut state = State::new();
        assert!(!state.feed(Layout::It,0xe0).pressed);
        state.feed(Layout::It,0x38);
        assert!(state.altgr());
        assert!(!state.down(0x38,false));
        assert_eq!(state.feed(Layout::It,0x27).characters(), &['@']);
        state.feed(Layout::It,0xe0); state.feed(Layout::It,0xb8);
        assert!(!state.altgr());
        state.feed(Layout::It,0x3a); state.feed(Layout::It,0x3a);
        assert_eq!(state.feed(Layout::It,0x1e).characters(), &['A']);
        state.feed(Layout::It,0xba); state.feed(Layout::It,0x3a);
        assert_eq!(state.feed(Layout::It,0x1e).characters(), &['a']);
    }
    #[test]
    fn text_injection_roundtrips_across_layouts() {
        for layout in [Layout::Us,Layout::De,Layout::It,Layout::Pl] {
            for character in "C:\\RETROOS\\NDN.EXE /? [x] {y} @ ^\n".chars() {
                let (bytes,length) = sequence(layout,character);
                assert_ne!(length,0,"{layout:?}: {character}");
                let mut state = State::new();
                let mut output = alloc::vec::Vec::new();
                for &byte in &bytes[..length] { output.extend_from_slice(state.feed(layout,byte).characters()); }
                assert_eq!(output, [character],"{layout:?}: {character}");
            }
        }
    }
    #[test]
    fn left_alt_keeps_shortcut_identity_without_selecting_altgr() {
        let mut state = State::new();
        state.feed(Layout::It,0x38);
        assert!(!state.altgr());
        assert_eq!(state.feed(Layout::It,0x2d).characters(),&['x']);
        state.feed(Layout::It,0xb8);
        state.feed(Layout::It,0xe0); state.feed(Layout::It,0x38);
        assert_eq!(state.feed(Layout::It,0x27).characters(),&['@']);
    }
    #[test]
    fn russian_and_polish_are_unicode_before_guest_encoding() {
        assert_eq!(symbol(Layout::Ru,0x1e,false,false,false,false),C('ф'));
        assert_eq!(symbol(Layout::Ru,0x1e,false,false,false,true),C('\x01'));
        assert_eq!(symbol(Layout::Pl,0x26,true,true,false,false),C('Ł'));
        assert_eq!(lib::codepage::codepage(852).unwrap().encode_exact('Ł'),Some(0x9d));
    }
}
