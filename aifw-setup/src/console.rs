use std::io::{self, BufRead, Write};

/// Print a section header
pub fn header(title: &str) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {title}");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
}

/// Print an info line
pub fn info(msg: &str) {
    println!("  {msg}");
}

/// Print a success message
pub fn success(msg: &str) {
    println!("  [OK] {msg}");
}

/// Print a warning
pub fn warn(msg: &str) {
    println!("  [!] {msg}");
}

/// Print an error
pub fn error(msg: &str) {
    println!("  [ERROR] {msg}");
}

/// Prompt for text input with a default value
pub fn prompt(label: &str, default: &str) -> String {
    if default.is_empty() {
        print!("  {label}: ");
    } else {
        print!("  {label} [{default}]: ");
    }
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input).unwrap();
    let input = input.trim().to_string();

    if input.is_empty() {
        default.to_string()
    } else {
        input
    }
}

/// Prompt for a required field (no default, keeps asking until non-empty)
pub fn prompt_required(label: &str) -> String {
    loop {
        let val = prompt(label, "");
        if !val.is_empty() {
            return val;
        }
        warn("This field is required.");
    }
}

/// Prompt for a password (no echo)
/// Falls back to regular prompt if terminal doesn't support no-echo
pub fn prompt_password(label: &str) -> String {
    print!("  {label}: ");
    io::stdout().flush().unwrap();

    // Try to disable echo on Unix
    #[cfg(unix)]
    {
        use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        if let Ok(old_term) = tcgetattr(&stdin) {
            let mut term = old_term.clone();
            term.local_flags.remove(LocalFlags::ECHO);
            let _ = tcsetattr(&stdin, SetArg::TCSANOW, &term);

            let mut input = String::new();
            stdin.lock().read_line(&mut input).unwrap();
            println!(); // newline after hidden input

            let _ = tcsetattr(&stdin, SetArg::TCSANOW, &old_term);
            return input.trim().to_string();
        }
        // tcgetattr failed (not a tty) — fall through to echoed read.
        let mut input = String::new();
        stdin.lock().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    #[cfg(not(unix))]
    {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim().to_string()
    }
}

/// Prompt for password with confirmation
pub fn prompt_password_confirm(label: &str) -> String {
    loop {
        let pw1 = prompt_password(label);
        let pw2 = prompt_password("Confirm password");

        if pw1 == pw2 {
            return pw1;
        }
        warn("Passwords do not match. Try again.");
    }
}

/// Prompt for a yes/no confirmation
pub fn confirm(label: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("  {label} [{hint}]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input).unwrap();
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        return default;
    }
    matches!(input.as_str(), "y" | "yes")
}

/// Prompt to select from a numbered list. Returns the 0-based index.
pub fn select(label: &str, options: &[&str], default: usize) -> usize {
    println!("  {label}:");
    for (i, opt) in options.iter().enumerate() {
        let marker = if i == default { " *" } else { "" };
        println!("    {}) {opt}{marker}", i + 1);
    }

    loop {
        let input = prompt("Choice", &(default + 1).to_string());
        if let Ok(n) = input.parse::<usize>()
            && n >= 1
            && n <= options.len()
        {
            return n - 1;
        }
        warn(&format!("Please enter 1-{}", options.len()));
    }
}

/// Validate password strength: 8+ chars, uppercase, lowercase, digit
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain an uppercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain a lowercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain a number".to_string());
    }
    Ok(())
}

/// Validate an IP address (v4 or v6)
pub fn validate_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Validate an IP/prefix (e.g., 192.168.1.1/24)
pub fn validate_cidr(cidr: &str) -> bool {
    if let Some((ip, prefix)) = cidr.split_once('/') {
        if !validate_ip(ip) {
            return false;
        }
        if let Ok(p) = prefix.parse::<u8>() {
            let is_v6 = ip.contains(':');
            let max = if is_v6 { 128 } else { 32 };
            return p <= max;
        }
    }
    false
}
