use aifw_core::system_apply_helpers::{
    replace_managed_block, validate_hostname, validate_domain, validate_ssh_port,
    validate_baud,
};

#[test]
fn replace_managed_block_inserts_when_absent() {
    let original = "line1\nline2\n";
    let out = replace_managed_block(original, "AiFw console", "console=\"comconsole\"\n");
    assert!(out.contains("# BEGIN AiFw console"));
    assert!(out.contains("console=\"comconsole\""));
    assert!(out.contains("# END AiFw console"));
    assert!(out.starts_with("line1\nline2\n"));
}

#[test]
fn replace_managed_block_overwrites_existing() {
    let original = "keepme\n# BEGIN AiFw console\nconsole=\"vidconsole\"\n# END AiFw console\ntail\n";
    let out = replace_managed_block(original, "AiFw console", "console=\"comconsole\"\n");
    assert!(out.contains("console=\"comconsole\""));
    assert!(!out.contains("console=\"vidconsole\""));
    assert!(out.contains("keepme"));
    assert!(out.contains("tail"));
    // No duplicated markers
    assert_eq!(out.matches("# BEGIN AiFw console").count(), 1);
    assert_eq!(out.matches("# END AiFw console").count(), 1);
}

#[test]
fn replace_managed_block_idempotent() {
    let original = "x\n";
    let once = replace_managed_block(original, "AiFw console", "a=1\n");
    let twice = replace_managed_block(&once, "AiFw console", "a=1\n");
    assert_eq!(once, twice);
}

#[test]
fn validate_hostname_accepts_rfc1123_label() {
    assert!(validate_hostname("router").is_ok());
    assert!(validate_hostname("aifw-01").is_ok());
    assert!(validate_hostname("a").is_ok());
}

#[test]
fn validate_hostname_rejects_dots_and_empty_and_long() {
    assert!(validate_hostname("").is_err());
    assert!(validate_hostname("host.domain").is_err()); // dots → use domain field
    assert!(validate_hostname("-leading").is_err());
    assert!(validate_hostname(&"a".repeat(64)).is_err()); // > 63
    assert!(validate_hostname("has space").is_err());
}

#[test]
fn validate_domain_allows_empty() {
    assert!(validate_domain("").is_ok());
}

#[test]
fn validate_domain_rejects_leading_dot_and_spaces() {
    assert!(validate_domain("home.lan").is_ok());
    assert!(validate_domain(".badlead").is_err());
    assert!(validate_domain("has space.com").is_err());
}

#[test]
fn validate_ssh_port_range() {
    assert!(validate_ssh_port(22).is_ok());
    assert!(validate_ssh_port(65535).is_ok());
    assert!(validate_ssh_port(1).is_ok());
    assert!(validate_ssh_port(0).is_err());
}

#[test]
fn validate_baud_allowed_set() {
    for b in [9600, 19200, 38400, 57600, 115200] {
        assert!(validate_baud(b).is_ok(), "baud {} should be allowed", b);
    }
    assert!(validate_baud(1).is_err());
    assert!(validate_baud(250000).is_err());
}

#[test]
fn replace_managed_block_ignores_marker_inside_comment_line() {
    // A documentation line that mentions the marker text mid-line must NOT
    // be treated as a real marker.
    let original = "# note: look for the # BEGIN AiFw console line below\nreal_setting=1\n";
    let out = replace_managed_block(original, "AiFw console", "console=\"comconsole\"\n");
    // Original comment line preserved verbatim
    assert!(out.contains("# note: look for the # BEGIN AiFw console line below"));
    // A real managed block was appended (not inserted into the comment)
    assert!(out.contains("console=\"comconsole\""));
    // Exactly one real BEGIN line (the appended one)
    let real_begin_lines = out.lines().filter(|l| l.trim_start().starts_with("# BEGIN AiFw console")).count();
    assert_eq!(real_begin_lines, 1, "exactly one line starts with # BEGIN AiFw console; comment line must not count");
    // real_setting line preserved
    assert!(out.contains("real_setting=1"));
}

#[test]
fn replace_managed_block_handles_begin_after_end_gracefully() {
    // Pathological / corrupted input: END appears before BEGIN.
    // Must not silently produce a double-block. Either append a new correct
    // block (preferred) or leave content unchanged — but NEVER corrupt.
    let original = "# END AiFw console\nmiddle\n# BEGIN AiFw console\ntail\n";
    let out = replace_managed_block(original, "AiFw console", "console=\"comconsole\"\n");
    // The output must contain the new block's content at least once
    assert!(out.contains("console=\"comconsole\""));
    // The output must contain the original "middle" and "tail" content
    assert!(out.contains("middle"));
    assert!(out.contains("tail"));
    // Must not contain more than one well-formed BEGIN/END pair
    let begin_count = out.lines().filter(|l| l.trim_start() == "# BEGIN AiFw console").count();
    let end_count = out.lines().filter(|l| l.trim_start() == "# END AiFw console").count();
    // At most one well-formed pair (not counting the pre-existing bare markers)
    assert!(begin_count <= 2 && end_count <= 2);
}
