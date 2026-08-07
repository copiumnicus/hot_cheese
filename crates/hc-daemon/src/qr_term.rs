//! One QR frame on a terminal, in colours the terminal cannot argue with.
//!
//! Two module rows share one text row via `▀`: the cell's foreground paints the upper module
//! and its background the lower one. Both are written as explicit 256-colour black and white on
//! every cell, so a light theme, a dark theme, or a reversed one all render the same code — a
//! scanner needs dark modules dark, and inherited terminal colours do not guarantee that.
//!
//! A code that does not fit is a refusal naming the size it needs. A QR clipped by the window,
//! or folded by a wrapping line, scans as nothing, and printing one wastes the operator's time
//! on a camera that will never lock; so does printing one into a pipe.
use err_mac::create_err_with_impls;
use qrcode::{Color, QrCode};

/// Light modules a scanner needs on every side before the code starts.
const QUIET: usize = 4;

/// 256-colour index of a light module.
const WHITE: u8 = 15;

/// 256-colour index of a dark module.
const BLACK: u8 = 0;

create_err_with_impls!(
    #[derive(Debug)]
    pub RenderErr,
    NotATerminal,
    Qr(qrcode::types::QrError)
    ;
    TerminalTooSmall {
        need_cols: usize,
        need_rows: usize,
        have_cols: u16,
        have_rows: u16
    }
);

/// Columns and rows of the terminal on stdout.
fn terminal_size() -> Result<(u16, u16), RenderErr> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 || ws.ws_col == 0 || ws.ws_row == 0 {
        return Err(RenderErr::NotATerminal);
    }
    Ok((ws.ws_col, ws.ws_row))
}

/// Pack the code two module rows to a text row, quiet zone included, every cell carrying both
/// its colours.
fn lay_out(code: &QrCode) -> String {
    let width = code.width();
    let span = width + 2 * QUIET;
    let dark = |x: usize, y: usize| {
        let inside = x >= QUIET && y >= QUIET && x < QUIET + width && y < QUIET + width;
        inside && code[(x - QUIET, y - QUIET)] == Color::Dark
    };
    let mut out = String::new();
    for row in 0..span.div_ceil(2) {
        for x in 0..span {
            let fg = if dark(x, row * 2) { BLACK } else { WHITE };
            let bg = if dark(x, row * 2 + 1) { BLACK } else { WHITE };
            out.push_str(&format!("\u{1b}[38;5;{fg};48;5;{bg}m\u{2580}"));
        }
        out.push_str("\u{1b}[0m\n");
    }
    out
}

/// Encode `frame` and lay it out for the terminal it is about to be printed on, refusing a
/// window that would clip or wrap it.
pub fn render(frame: &[u8]) -> Result<String, RenderErr> {
    let code = QrCode::new(frame)?;
    let span = code.width() + 2 * QUIET;
    let need_rows = span.div_ceil(2);
    let (have_cols, have_rows) = terminal_size()?;
    if usize::from(have_cols) < span || usize::from(have_rows) < need_rows {
        return Err(RenderErr::TerminalTooSmall {
            need_cols: span,
            need_rows,
            have_cols,
            have_rows,
        });
    }
    Ok(lay_out(&code))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A camera reads what the cells actually say, so the packing has to survive being read
    /// back: every module must land at the right column, in the right half of the right row,
    /// offset by the quiet zone, with the dark ones black — an off-by-one in the parity or the
    /// offset yields a wall of blocks that still looks like a QR and scans as nothing.
    #[test]
    fn every_module_reads_back_from_the_packed_halves() {
        let code = QrCode::new(b"hot_cheese bundle").expect("a short payload encodes");
        let width = code.width();
        let span = width + 2 * QUIET;
        let packed = lay_out(&code);
        let rows: Vec<&str> = packed.lines().collect();
        assert_eq!(rows.len(), span.div_ceil(2));

        for (row, text) in rows.iter().enumerate() {
            let cells: Vec<&str> = text.split("\u{1b}[38;5;").skip(1).collect();
            assert_eq!(
                cells.len(),
                span,
                "one cell per column, quiet zone included"
            );
            for (x, cell) in cells.iter().enumerate() {
                let (fg, rest) = cell.split_once(';').expect("a foreground index");
                let bg = rest
                    .strip_prefix("48;5;")
                    .and_then(|s| s.split_once('m'))
                    .expect("a background index")
                    .0;
                assert!(
                    cell.contains('\u{2580}'),
                    "each cell is one upper half block"
                );
                for (half, colour) in [(0, fg), (1, bg)] {
                    let y = row * 2 + half;
                    let inside = x >= QUIET && y >= QUIET && x < QUIET + width && y < QUIET + width;
                    let expected = if inside && code[(x - QUIET, y - QUIET)] == Color::Dark {
                        BLACK
                    } else {
                        WHITE
                    };
                    assert_eq!(
                        colour.parse::<u8>().expect("a 256-colour index"),
                        expected,
                        "module ({x}, {y})"
                    );
                }
            }
        }
    }
}
