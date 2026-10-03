//! Single-cell Unicode lookalikes for limited text displays.
//!
//! This is a visual fallback, not Unicode normalization or a file-name
//! conversion. A code page must try an exact encoding before using it.

pub fn simplify(ch: char) -> Option<char> {
    Some(match ch {
        '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' => '-',
        '‘' | '’' | '‚' | '‛' | '′' => '\'',
        '“' | '”' | '„' | '‟' | '″' => '"',
        '…' => '.',
        '\u{00a0}' | '\u{2007}' | '\u{202f}' => ' ',
        '⇐' | '⬅' | '⟵' => '←',
        '⇒' | '➡' | '⟶' | '↪' => '→',
        '⇑' | '⬆' => '↑',
        '⇓' | '⬇' => '↓',
        '⇔' | '⟷' => '↔',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::simplify;

    #[test]
    fn single_cell_visual_fallbacks() {
        assert_eq!(simplify('—'), Some('-'));
        assert_eq!(simplify('⇒'), Some('→'));
        assert_eq!(simplify('🦀'), None);
    }
}
