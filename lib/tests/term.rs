use lib::term::Term;

fn write(term: &mut Term, bytes: &[u8]) {
    for &byte in bytes {
        term.put_utf8(byte);
    }
}

#[test]
fn full_screen_defers_wrap_until_next_printable_character() {
    let mut term = Term::new(None);
    write(&mut term, &vec![b'A'; 2000]);
    assert!(term.cells().iter().all(|cell| *cell as u8 == b'A'));
    write(&mut term, b"\x1b[1;1HB\x1b[25;80HC");
    assert_eq!(term.cells()[0] as u8, b'B');
    assert_eq!(term.cells()[1999] as u8, b'C');
    write(&mut term, b"D");
    assert_eq!(term.cells()[1920] as u8, b'D');
    assert_eq!(term.cells()[0] as u8, b'A');
}

#[test]
fn sgr_colors_utf8_and_control_strings_preserve_cursor() {
    let mut term = Term::new(None);
    write(&mut term, b"\x1b[2;3H\x1b[38;2;255;0;0mR");
    assert_eq!(term.cells()[82], 0x0452);
    write(&mut term, b"\xe2\x94");
    write(&mut term, b"\x80");
    assert_eq!(term.cells()[83] as u8, 0xc4);
    write(&mut term, b"\x1b]0;title\x07\x1b_Garbage\x1b\\X");
    assert_eq!(term.cells()[84] as u8, b'X');
    write(&mut term, b"\x1b7\x1b[1;1HQ\x1b8Z");
    assert_eq!(term.cells()[0] as u8, b'Q');
    assert_eq!(term.cells()[85] as u8, b'Z');
}

#[test]
fn terminal_queries_reply_without_drawing_text() {
    let mut term = Term::new(None);
    write(&mut term, b"\x1b[3;12H\x1b[5n\x1b[6n\x1b[c\x1b[16t");
    let mut reply = [0; 64];
    let n = term.take_response(&mut reply);
    assert_eq!(&reply[..n], b"\x1b[0n\x1b[3;12R\x1b[?1;0c\x1b[6;16;9t");
    assert_eq!(term.take_response(&mut reply), 0);
    assert!(term.cells().iter().all(|cell| *cell as u8 == b' '));
}

#[test]
fn alternate_screen_restores_shell_grid_cursor_and_attributes() {
    let mut term = Term::new(None);
    write(&mut term, b"\x1b[32m/ # ");
    let shell = term.cells().to_vec();
    let cursor = term.cursor_pos();
    write(&mut term, b"\x1b[?1049h\x1b[31mRat Commander\x1b[?1049h");
    assert_ne!(term.cells().as_slice(), shell.as_slice());
    write(&mut term, b"\x1b[?1049l\x1b[?1049l");
    assert_eq!(term.cells().as_slice(), shell.as_slice());
    assert_eq!(term.cursor_pos(), cursor);
    write(&mut term, b"x");
    assert_eq!(term.cells()[4], 0x0278);
}

#[test]
fn terminal_output_does_not_enter_the_debug_log_stream() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static DEBUG: AtomicUsize = AtomicUsize::new(0);
    static CONSOLE: AtomicUsize = AtomicUsize::new(0);
    fn debug(_: u8) { DEBUG.fetch_add(1, Ordering::Relaxed); }
    fn console(_: u8) { CONSOLE.fetch_add(1, Ordering::Relaxed); }
    lib::log::set_debug_sink(debug);
    lib::term::set_console_sink(console);
    lib::term::term().set_aperture(None);
    let redraw = b"\x1b[2Jscreen\x1b[H";
    for &byte in redraw { lib::term::put_utf8(byte); }
    assert_eq!(DEBUG.load(Ordering::Relaxed), 0);
    assert_eq!(CONSOLE.load(Ordering::Relaxed), redraw.len());
    lib::log::debug_byte(b'K');
    assert_eq!(DEBUG.load(Ordering::Relaxed), 1);
    assert_eq!(CONSOLE.load(Ordering::Relaxed), redraw.len());
}
