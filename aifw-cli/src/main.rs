//! `aifw` binary: set up logging and a runtime, then hand off to the library.

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // Errors reach the user as the command's own message; set
                // RUST_LOG=warn (or debug) to see library diagnostics too.
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: starting runtime: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let code = rt.block_on(aifw_cli::run(
        std::env::args_os(),
        aifw_cli::Io::stdio(),
        aifw_cli::Env::default(),
    ));
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
