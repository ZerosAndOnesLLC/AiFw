mod app;
mod ui;

use app::{App, Tab};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "aifw-tui", about = "AiFw Terminal UI")]
struct Args {
    /// Path to the database file
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    /// Refresh interval in seconds
    #[arg(long, default_value = "5")]
    refresh: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Ensure DB dir exists
    if let Some(parent) = args.db.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut app = App::new(&args.db).await?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let refresh_dur = Duration::from_secs(args.refresh);
    let mut last_refresh = std::time::Instant::now();

    // Main loop
    while app.running {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Poll for events with timeout
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.running = false,
                        KeyCode::Tab | KeyCode::Right => app.tab = app.tab.next(),
                        KeyCode::BackTab | KeyCode::Left => app.tab = app.tab.prev(),
                        KeyCode::Char('1') => app.tab = Tab::Dashboard,
                        KeyCode::Char('2') => app.tab = Tab::Rules,
                        KeyCode::Char('3') => app.tab = Tab::Nat,
                        KeyCode::Char('4') => app.tab = Tab::Connections,
                        KeyCode::Char('5') => app.tab = Tab::Logs,
                        KeyCode::Up | KeyCode::Char('k') => app.select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.select_down(),
                        KeyCode::Char('r') => app.refresh().await,
                        KeyCode::Char('d') | KeyCode::Delete => {
                            match app.tab {
                                Tab::Rules => app.delete_selected_rule().await,
                                Tab::Nat => app.delete_selected_nat().await,
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Auto-refresh
        if last_refresh.elapsed() >= refresh_dur {
            app.refresh().await;
            last_refresh = std::time::Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
