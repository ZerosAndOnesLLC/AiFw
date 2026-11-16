//! Where a command reads and writes. The binary uses the real stdio; tests
//! drive `aifw_cli::run` with in-memory buffers and inspect the output.

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

/// Shared in-memory sink (test capture).
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Io {
    pub out: Box<dyn Write + Send>,
    pub err: Box<dyn Write + Send>,
    pub input: Box<dyn BufRead + Send>,
    /// Interactive terminal (secret prompts disable echo).
    pub tty: bool,
    captured: Option<(Capture, Capture)>,
}

impl Io {
    /// Real process stdio.
    pub fn stdio() -> Self {
        use std::io::IsTerminal;
        Self {
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
            input: Box::new(std::io::BufReader::new(std::io::stdin())),
            tty: std::io::stdin().is_terminal(),
            captured: None,
        }
    }

    /// In-memory stdio with `input` as stdin.
    pub fn buffered(input: &str) -> Self {
        let out = Capture::default();
        let err = Capture::default();
        Self {
            out: Box::new(out.clone()),
            err: Box::new(err.clone()),
            input: Box::new(std::io::Cursor::new(input.as_bytes().to_vec())),
            tty: false,
            captured: Some((out, err)),
        }
    }

    /// Handles to the captured stdout/stderr (buffered mode only).
    pub fn captures(&self) -> Option<(Capture, Capture)> {
        self.captured.clone()
    }

    pub fn stdout_string(&self) -> String {
        self.captured
            .as_ref()
            .map(|(o, _)| o.contents())
            .unwrap_or_default()
    }

    pub fn stderr_string(&self) -> String {
        self.captured
            .as_ref()
            .map(|(_, e)| e.contents())
            .unwrap_or_default()
    }

    /// Write a line to stdout. Broken pipes (`aifw … | head`) are ignored.
    pub fn println(&mut self, s: &str) {
        let _ = writeln!(self.out, "{s}");
    }

    /// Write to stderr without a newline (prompts).
    pub fn eprint(&mut self, s: &str) {
        let _ = write!(self.err, "{s}");
        let _ = self.err.flush();
    }

    pub fn eprintln(&mut self, s: &str) {
        let _ = writeln!(self.err, "{s}");
    }
}
