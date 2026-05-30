use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, path::PathBuf};

mod app;
mod dissect;
mod model;
mod pcap;
mod ui;

use app::App;

#[derive(Parser)]
#[command(name = "shuck", version, about = "Hand-rolled packet dissector TUI")]
struct Cli {
    /// Path to a .pcap or .pcapng file
    file: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let frames =
        pcap::load(&cli.file).with_context(|| format!("loading {}", cli.file.display()))?;

    if frames.is_empty() {
        eprintln!("No frames in capture");
        return Ok(());
    }

    let mut app = App::new(frames);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    use app::Pane;

    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Tab => app.toggle_focus(),
                KeyCode::Down | KeyCode::Char('j') => match app.focus {
                    Pane::FrameList => app.next_frame(),
                    Pane::Tree => app.next_tree_row(),
                },
                KeyCode::Up | KeyCode::Char('k') => match app.focus {
                    Pane::FrameList => app.previous_frame(),
                    Pane::Tree => app.previous_tree_row(),
                },
                KeyCode::Home | KeyCode::Char('g') => app.first_frame(),
                KeyCode::End | KeyCode::Char('G') => app.last_frame(),
                _ => {}
            }
        }
    }
}
