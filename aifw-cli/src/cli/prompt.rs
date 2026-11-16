//! Interactive input: confirmations, secrets, plain lines. Every prompt
//! honours `--no-input` and EOF (a cron job with no TTY answers "no").

use std::io::{BufRead, IsTerminal};

use super::exit::CliError;
use super::io::Io;

/// Ask a yes/no question on stderr. `assume_yes` skips the prompt; with
/// `no_input` an unanswered question is an error naming `skip_flag` (the
/// flag that answers it). EOF or anything but y/yes answers no.
pub fn confirm(
    io: &mut Io,
    question: &str,
    assume_yes: bool,
    no_input: bool,
    skip_flag: &str,
) -> anyhow::Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    if no_input {
        return Err(CliError::Aborted(format!(
            "\"{question}\" needs an answer and --no-input is set; pass {skip_flag}"
        ))
        .into());
    }
    io.eprint(&format!("{question} [y/N] "));
    let line = read_line_raw(io)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Like [`confirm`] but a "no" aborts the command.
pub fn require(
    io: &mut Io,
    question: &str,
    assume_yes: bool,
    no_input: bool,
    skip_flag: &str,
) -> anyhow::Result<()> {
    if confirm(io, question, assume_yes, no_input, skip_flag)? {
        Ok(())
    } else {
        Err(CliError::Aborted("aborted".into()).into())
    }
}

/// Read a line after showing `prompt` (no prompt when `no_input`, which
/// then errors with `what`).
pub fn line(io: &mut Io, prompt: &str, no_input: bool, what: &str) -> anyhow::Result<String> {
    if no_input {
        return Err(CliError::Usage(format!("{what} is required (--no-input set)")).into());
    }
    io.eprint(prompt);
    let s = read_line_raw(io)?;
    let s = s.trim().to_string();
    if s.is_empty() {
        return Err(CliError::Usage(format!("{what} is required")).into());
    }
    Ok(s)
}

/// Read a secret without echo when attached to a terminal; otherwise one
/// line from the input stream (`--password-stdin` style piping).
pub fn secret(io: &mut Io, prompt: &str, no_input: bool, what: &str) -> anyhow::Result<String> {
    if no_input {
        return Err(CliError::Usage(format!("{what} is required (--no-input set)")).into());
    }
    let s = if io.tty && std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        io.eprint(prompt);
        read_line_raw(io)?
    };
    let s = s.trim_end_matches(['\r', '\n']).to_string();
    if s.is_empty() {
        return Err(CliError::Usage(format!("{what} is required")).into());
    }
    Ok(s)
}

/// One line from the input stream; EOF yields "".
pub fn read_line_raw(io: &mut Io) -> anyhow::Result<String> {
    let mut s = String::new();
    io.input.read_line(&mut s)?;
    Ok(s)
}

/// The whole input stream (for `--api-key-stdin`, `-f -`).
pub fn read_all(io: &mut Io) -> anyhow::Result<String> {
    let mut s = String::new();
    std::io::Read::read_to_string(&mut io.input, &mut s)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_means_no() {
        let mut io = Io::buffered("");
        assert!(!confirm(&mut io, "Delete?", false, false, "--yes").unwrap());
        assert!(io.stderr_string().contains("Delete? [y/N]"));
    }

    #[test]
    fn yes_answers() {
        for ans in ["y\n", "YES\n", " yes \n"] {
            let mut io = Io::buffered(ans);
            assert!(
                confirm(&mut io, "Q", false, false, "--yes").unwrap(),
                "{ans:?}"
            );
        }
        let mut io = Io::buffered("nope\n");
        assert!(!confirm(&mut io, "Q", false, false, "--yes").unwrap());
    }

    #[test]
    fn assume_yes_and_no_input() {
        let mut io = Io::buffered("");
        assert!(confirm(&mut io, "Q", true, true, "--yes").unwrap());
        let e = confirm(&mut io, "Q", false, true, "--force").unwrap_err();
        assert!(e.to_string().contains("--force"));
        assert!(require(&mut io, "Q", false, false, "--yes").is_err());
    }

    #[test]
    fn piped_secret_and_line() {
        let mut io = Io::buffered("s3cret\nalice\n");
        assert_eq!(
            secret(&mut io, "Password: ", false, "password").unwrap(),
            "s3cret"
        );
        assert_eq!(line(&mut io, "User: ", false, "username").unwrap(), "alice");
        assert!(line(&mut io, "User: ", false, "username").is_err(), "EOF");
        assert!(secret(&mut io, "P", true, "password").is_err());
    }
}
