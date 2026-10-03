//! CP437 text glyphs and a small Unicode-to-DOS display fallback.
//!
//! Files and kernel logs retain UTF-8. Only VGA/DOS presentation uses these
//! single-byte glyphs. Unrepresentable characters become the CP437 square.

/// VGA text glyph order. The low control range names the visible ROM glyphs.
#[rustfmt::skip]
pub const TABLE: [char; 256] = [
    '\0','☺','☻','♥','♦','♣','♠','•','◘','○','◙','♂','♀','♪','♫','☼',
    '►','◄','↕','‼','¶','§','▬','↨','↑','↓','→','←','∟','↔','▲','▼',
    ' ','!','"','#','$','%','&','\'','(',')','*','+',',','-','.','/',
    '0','1','2','3','4','5','6','7','8','9',':',';','<','=','>','?',
    '@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
    'P','Q','R','S','T','U','V','W','X','Y','Z','[','\\',']','^','_',
    '`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
    'p','q','r','s','t','u','v','w','x','y','z','{','|','}','~','⌂',
    'Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å',
    'É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','¢','£','¥','₧','ƒ',
    'á','í','ó','ú','ñ','Ñ','ª','º','¿','⌐','¬','½','¼','¡','«','»',
    '░','▒','▓','│','┤','╡','╢','╖','╕','╣','║','╗','╝','╜','╛','┐',
    '└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','╧',
    '╨','╤','╥','╙','╘','╒','╓','╫','╪','┘','┌','█','▄','▌','▐','▀',
    'α','ß','Γ','π','Σ','σ','µ','τ','Φ','Θ','Ω','δ','∞','φ','ε','∩',
    '≡','±','≥','≤','⌠','⌡','÷','≈','°','∙','·','√','ⁿ','²','■','\u{00a0}',
];

pub fn decode(byte: u8) -> char { TABLE[byte as usize] }

/// One display cell for a Unicode scalar. Text that needs multiple cells uses
/// a readable one-cell approximation so cursor accounting remains unchanged.
pub fn encode(ch: char) -> u8 {
    if ch.is_ascii() { return ch as u8; }
    match ch {
        '—' | '–' | '−' | '‑' => return b'-',
        '‘' | '’' | '′' => return b'\'',
        '“' | '”' | '″' => return b'"',
        '…' => return b'.',
        _ => {}
    }
    TABLE.iter().position(|&glyph| glyph == ch)
        .map(|index| index as u8).unwrap_or(0xfe)
}

/// Convert one UTF-8 log line for a DOS code-page display. Legacy lines with
/// invalid UTF-8 are retained byte-for-byte as CP437 output.
pub fn display_line(input: &[u8], output: &mut [u8]) -> usize {
    if let Ok(text) = core::str::from_utf8(input) {
        let mut len = 0;
        for ch in text.chars() {
            if len == output.len() { break; }
            output[len] = encode(ch);
            len += 1;
        }
        len
    } else {
        let len = input.len().min(output.len());
        output[..len].copy_from_slice(&input[..len]);
        len
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, display_line, encode};

    #[test]
    fn every_cp437_byte_round_trips() {
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(encode(decode(byte)), byte, "CP437 byte {byte:#04x}");
        }
    }

    #[test]
    fn display_transliterates_punctuation_and_preserves_cp437_glyphs() {
        assert_eq!(encode('—'), b'-');
        assert_eq!(encode('→'), 0x1a);
        assert_eq!(encode('é'), 0x82);
        assert_eq!(encode('🦀'), 0xfe);
        assert_eq!(decode(0x82), 'é');
        let mut out = [0; 16];
        let n = display_line("A→B — 🦀".as_bytes(), &mut out);
        assert_eq!(&out[..n], b"A\x1aB - \xfe");
        assert_eq!(display_line(&[0x82], &mut out), 1);
        assert_eq!(out[0], 0x82);
    }
}
