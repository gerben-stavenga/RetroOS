//! Set-1 keyboard layouts produce Unicode, independent of guest encodings.
//! The national key positions follow xkeyboard-config's de/basic, it/winkeys,
//! ru/winkeys and Polish programmer layouts. No allocation is needed here.
use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Layout { Us, De, It, Ru, Pl }
static CURRENT: AtomicU8 = AtomicU8::new(0);
pub fn current() -> Layout {
    match CURRENT.load(Ordering::Acquire) { 1 => Layout::De, 2 => Layout::It, 3 => Layout::Ru, 4 => Layout::Pl, _ => Layout::Us }
}
pub fn select(name: &str) -> bool {
    let Some(layout) = Layout::parse(name) else { return false; };
    CURRENT.store(layout as u8, Ordering::Release);
    true
}
impl Layout {
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Us, Self::De, Self::It, Self::Ru, Self::Pl].into_iter().find(|layout| layout.name().eq_ignore_ascii_case(name))
    }
    pub fn name(self) -> &'static str { match self { Self::Us => "us", Self::De => "de", Self::It => "it", Self::Ru => "ru", Self::Pl => "pl" } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symbol { None, Character(char), Dead(char) }
use Symbol::{Character as C, Dead as D, None as N};

const US_LOWER: &[u8; 58] = b"\x00\x1b1234567890-=\x08\tqwertyuiop[]\n\x00asdfghjkl;'`\x00\\zxcvbnm,./\x00*\x00 ";
const US_UPPER: &[u8; 58] = b"\x00\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\x00ASDFGHJKL:\"~\x00|ZXCVBNM<>?\x00*\x00 ";

/// Four levels: plain, Shift, AltGr, Shift+AltGr. Missing AltGr levels do not
/// manufacture plain characters. Caps Lock changes letter case, not symbols.
pub fn symbol(layout: Layout, scan: u8, shift: bool, altgr: bool, caps: bool, ctrl: bool) -> Symbol {
    let plain = US_LOWER.get(scan as usize).copied().unwrap_or(0);
    let upper = US_UPPER.get(scan as usize).copied().unwrap_or(0);
    let mut levels = [if plain == 0 { N } else { C(char::from(plain)) }, if upper == 0 { N } else { C(char::from(upper)) }, N, N];
    if scan == 0x56 { levels = [C('<'), C('>'), C('|'), N]; }
    match layout {
        Layout::Us => {},
        Layout::De | Layout::It => {
            // The shared Latin number row (ISO positions).
            let pair = match scan { 0x03 => Some(('2','"')), 0x04 => Some(('3', if layout == Layout::De { '§' } else { '£' })),
                0x07 => Some(('6','&')), 0x08 => Some(('7','/')), 0x09 => Some(('8','(')),
                0x0a => Some(('9',')')), 0x0b => Some(('0','=')), 0x33 => Some((',',';')),
                0x34 => Some(('.',':')), 0x35 => Some(('-','_')), _ => None };
            if let Some((a,b)) = pair { levels = [C(a),C(b),N,N]; }
            if layout == Layout::De {
                levels = match scan {
                    0x08 => [C('7'),C('/'),C('{'),N], 0x09 => [C('8'),C('('),C('['),N],
                    0x0a => [C('9'),C(')'),C(']'),N], 0x0b => [C('0'),C('='),C('}'),N],
                    0x0c => [C('ß'),C('?'),C('\\'),N], 0x0d => [D('´'),D('`'),N,N],
                    0x10 => [C('q'),C('Q'),C('@'),N], 0x12 => [C('e'),C('E'),C('€'),C('€')],
                    0x15 => [C('z'),C('Z'),N,N], 0x1a => [C('ü'),C('Ü'),N,N],
                    0x1b => [C('+'),C('*'),C('~'),N], 0x27 => [C('ö'),C('Ö'),N,N],
                    0x28 => [C('ä'),C('Ä'),N,N], 0x29 => [D('^'),C('°'),N,N],
                    0x2b => [C('#'),C('\''),N,N], 0x2c => [C('y'),C('Y'),N,N],
                    0x32 => [C('m'),C('M'),C('µ'),N], _ => levels,
                };
            } else {
                levels = match scan {
                    0x06 => [C('5'),C('%'),C('€'),C('€')], 0x0c => [C('\''),C('?'),C('`'),N],
                    0x0d => [C('ì'),C('^'),C('~'),N], 0x1a => [C('è'),C('é'),C('['),C('{')],
                    0x1b => [C('+'),C('*'),C(']'),C('}')], 0x27 => [C('ò'),C('ç'),C('@'),N],
                    0x28 => [C('à'),C('°'),C('#'),N], 0x29 => [C('\\'),C('|'),N,N],
                    0x2b => [C('ù'),C('§'),D('`'),N], _ => levels,
                };
            }
        },
        Layout::Pl => {
            let pair = match scan { 0x12 => Some(('ę','Ę')), 0x18 => Some(('ó','Ó')), 0x1e => Some(('ą','Ą')),
                0x1f => Some(('ś','Ś')), 0x26 => Some(('ł','Ł')), 0x2c => Some(('ż','Ż')),
                0x2d => Some(('ź','Ź')), 0x2e => Some(('ć','Ć')), 0x31 => Some(('ń','Ń')),
                0x06 => Some(('€','€')), _ => None };
            if let Some((a,b)) = pair { levels[2] = C(a); levels[3] = C(b); }
        },
        Layout::Ru => {
            let row = match scan { 0x10..=0x1b => Some(("йцукенгшщзхъ", scan - 0x10)),
                0x1e..=0x28 => Some(("фывапролджэ", scan - 0x1e)), 0x2c..=0x34 => Some(("ячсмитьбю", scan - 0x2c)), _ => None };
            if let Some((row,index)) = row {
                let a = row.chars().nth(index as usize).unwrap();
                levels = [C(a),C(a.to_uppercase().next().unwrap()),N,N];
            }
            levels = match scan {
                0x03 => [C('2'),C('"'),N,N], 0x04 => [C('3'),C('№'),N,N],
                0x05 => [C('4'),C(';'),N,N], 0x07 => [C('6'),C(':'),N,N], 0x08 => [C('7'),C('?'),N,N],
                0x29 => [C('ё'),C('Ё'),N,N], 0x2b => [C('\\'),C('/'),N,N], 0x35 => [C('.'),C(','),N,N], _ => levels,
            };
        },
    }
    // Ctrl shortcuts retain the Latin key identity even with Cyrillic selected.
    if ctrl && !altgr {
        let base = if layout == Layout::Ru { char::from(plain) } else { match levels[0] { C(c) => c, _ => '\0' } };
        return match base.to_ascii_lowercase() {
            'a'..='z' => C((base.to_ascii_lowercase() as u8 - b'a' + 1) as char),
            '[' => C('\x1b'), '\\' => C('\x1c'), ']' => C('\x1d'), '^' => C('\x1e'), '_' => C('\x1f'), _ => N,
        };
    }
    let mut result = levels[usize::from(shift) + 2 * usize::from(altgr)];
    if caps && let C(c) = result {
        // Only pairs that differ by case use Shift XOR Caps (Italian è/é do not).
        let (a,b) = (levels[2 * usize::from(altgr)], levels[1 + 2 * usize::from(altgr)]);
        if let (C(a),C(b)) = (a,b) && a != b && a.to_uppercase().next() == Some(b) {
            result = C(if shift { a } else { b });
        } else if c.is_alphabetic() {
            let mut upper = c.to_uppercase();
            let first = upper.next().unwrap_or(c);
            // A key event represents one scalar; do not truncate expansions
            // such as German sharp s -> SS to a misleading single S.
            result = C(if upper.next().is_none() { first } else { c });
        }
    }
    result
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Event {
    pub scan: u8, pub extended: bool, pub pressed: bool, pub repeat: bool,
    pub text: [char; 2], pub length: usize, pub dead: bool,
}
impl Event { pub fn characters(&self) -> &[char] { &self.text[..self.length] } }

/// Per input stream state: extended modifiers, locks and dead-key composition.
/// BIOS sessions own an instance, so one DOS session cannot consume another's
/// pending accent. Protected console input uses the foreground input stream.
#[derive(Clone, Copy)]
pub struct State {
    keys: [u8; 32], prefix: bool, pause: u8,
    pub caps: bool, pub num: bool, pub scroll: bool,
    dead: Option<char>, latin: bool,
}
impl Default for State { fn default() -> Self { Self::new() } }
impl State {
    pub const fn new() -> Self { Self { keys: [0;32], prefix: false, pause: 0, caps: false, num: false, scroll: false, dead: None, latin: false } }
    pub fn down(&self, scan: u8, extended: bool) -> bool {
        let index = usize::from(scan & 0x7f) + if extended { 128 } else { 0 };
        self.keys[index / 8] & (1 << (index % 8)) != 0
    }
    pub fn shift(&self) -> bool { self.down(0x2a,false) || self.down(0x36,false) }
    pub fn ctrl(&self) -> bool { self.down(0x1d,false) || self.down(0x1d,true) }
    pub fn alt(&self) -> bool { self.down(0x38,false) || self.down(0x38,true) }
    pub fn altgr(&self) -> bool { self.down(0x38,true) }
    pub fn feed(&mut self, layout: Layout, byte: u8) -> Event {
        if self.pause != 0 { self.pause -= 1; return Event::default(); }
        if byte == 0xe1 { self.pause = 5; return Event::default(); }
        if byte == 0xe0 { self.prefix = true; return Event::default(); }
        let extended = core::mem::take(&mut self.prefix);
        let scan = byte & 0x7f;
        // Print Screen's E0 fake shifts must never change Shift state.
        if extended && matches!(scan, 0x2a | 0x36) { return Event::default(); }
        let pressed = byte & 0x80 == 0;
        let repeat = self.down(scan,extended);
        let index = usize::from(scan) + if extended {128} else {0};
        if pressed { self.keys[index/8] |= 1 << (index%8); } else { self.keys[index/8] &= !(1 << (index%8)); }
        let mut event = Event { scan, extended, pressed, repeat, ..Event::default() };
        if !pressed { return event; }
        if !repeat && !extended {
            match scan { 0x3a => self.caps = !self.caps, 0x45 => self.num = !self.num, 0x46 => self.scroll = !self.scroll, _ => {} }
        }
        if matches!(scan, 0x1d | 0x2a | 0x36 | 0x38 | 0x3a | 0x45 | 0x46) {
            if layout == Layout::Ru && !repeat && ((scan == 0x38 && self.shift()) || (matches!(scan,0x2a | 0x36) && self.down(0x38,false))) {
                self.latin = !self.latin; self.dead = None;
            }
            return event;
        }
        let layout = if layout == Layout::Ru && self.latin { Layout::Us } else { layout };
        let mut value = if extended { match scan { 0x1c => C('\n'), 0x35 => C('/'), _ => N } }
            else { symbol(layout,scan,self.shift(),self.altgr(),self.caps,self.ctrl()) };
        if !extended && (0x47..=0x53).contains(&scan) {
            value = match scan { 0x4a => C('-'), 0x4e => C('+'),
                _ if self.num != self.shift() => {
                    let c = match scan {0x47=>'7',0x48=>'8',0x49=>'9',0x4b=>'4',0x4c=>'5',0x4d=>'6',0x4f=>'1',0x50=>'2',0x51=>'3',0x52=>'0',0x53=>'.',_=>'\0'};
                    C(c)
                }, _ => N };
        }
        // Left Alt retains the key identity without consuming an accent.
        // Personalities choose their native shortcut/Meta representation.
        if self.down(0x38,false) && !self.altgr() {
            if let C(c) = value { event.text[0] = c; event.length = 1; }
            return event;
        }
        match value {
            N => {},
            D(accent) => {
                if let Some(old) = self.dead.replace(accent) { event.text[0] = old; event.length = 1; }
                event.dead = true;
            },
            C(c) => {
                if let Some(accent) = self.dead.take() {
                    if c == '\x08' || c == '\x1b' { return event; }
                    if c == ' ' || c == accent { event.text[0] = accent; event.length = 1; }
                    else if let Some(composed) = compose(accent,c) { event.text[0] = composed; event.length = 1; }
                    else { event.text = [accent,c]; event.length = 2; }
                } else { event.text[0] = c; event.length = 1; }
            },
        }
        event
    }
}
fn compose(accent: char, character: char) -> Option<char> {
    let (plain,combined) = match accent {
        '´' => ("aAeEiIoOuUyYcCnNsSzZ", "áÁéÉíÍóÓúÚýÝćĆńŃśŚźŹ"),
        '`' => ("aAeEiIoOuU", "àÀèÈìÌòÒùÙ"), '^' => ("aAeEiIoOuU", "âÂêÊîÎôÔûÛ"),
        _ => return None,
    };
    plain.chars().position(|c| c == character).and_then(|index| combined.chars().nth(index))
}

/// Reverse translation for host/serial text injection, using the same map.
/// Physical scancode injection stays available for tests and real keyboards.
pub fn sequence(layout: Layout, character: char) -> ([u8;16],usize) {
    let mut result = [0;16];
    let mut length = 0;
    let character = if character == '\r' { '\n' } else if character == '\x7f' { '\x08' } else { character };
    for ctrl in [false,true] {
        for altgr in [false,true] {
            for shift in [false,true] {
                for scan in 1..=0x56 {
                    let value = symbol(layout,scan,shift,altgr,false,ctrl);
                    if !matches!(value, C(c) | D(c) if c == character) { continue; }
                    let mut append = |byte| { result[length] = byte; length += 1; };
                    if ctrl { append(0x1d); }
                    if shift { append(0x2a); }
                    if altgr { append(0xe0); append(0x38); }
                    append(scan); append(scan|0x80);
                    if altgr { append(0xe0); append(0xb8); }
                    if shift { append(0xaa); }
                    if ctrl { append(0x9d); }
                    if matches!(value,D(_)) { append(0x39); append(0xb9); }
                    return (result,length);
                }
            }
        }
    }
    for accent in ['´','`','^'] {
        for base in "aAeEiIoOuUyYcCnNsSzZ".chars() {
            if compose(accent,base) != Some(character) { continue; }
            let (first,n) = sequence(layout,accent);
            let (second,m) = sequence(layout,base);
            // The spacing accent sequence ends with Space; remove that tap
            // so the following letter composes instead.
            if n >= 2 && first[n-2] == 0x39 && m != 0 && n-2+m <= result.len() {
                result[..n-2].copy_from_slice(&first[..n-2]);
                result[n-2..n-2+m].copy_from_slice(&second[..m]);
                return (result,n-2+m);
            }
        }
    }
    // A Russian console exposes a Latin group through Left Alt+Shift.
    // Host text injection temporarily selects it for ASCII command text.
    if layout == Layout::Ru && character.is_ascii() {
        let (latin,n) = sequence(Layout::Us,character);
        if n != 0 && n+8 <= result.len() {
            result[..4].copy_from_slice(&[0x38,0x2a,0xaa,0xb8]);
            result[4..4+n].copy_from_slice(&latin[..n]);
            result[4+n..8+n].copy_from_slice(&[0x38,0x2a,0xaa,0xb8]);
            return (result,n+8);
        }
    }
    (result,0)
}
