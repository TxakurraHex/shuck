use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, List, ListItem},
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    // Show timestamps relative to frame 1 - easier to read than wall clock.
    let t0 = app
        .frames
        .first()
        .map(|fr| fr.timestamp)
        .unwrap_or_default();

    let items: Vec<ListItem> = app
        .frames
        .iter()
        .map(|fr| {
            let rel = fr.timestamp.saturating_sub(t0).as_secs_f64();
            let line = format!(
                "{:>5}  {:>10.6}s  {:<9}  {:>5}B",
                fr.number,
                rel,
                fr.link_type.name(),
                fr.raw.len(),
            );
            ListItem::new(line)
        })
        .collect();

    let title = format!(" Frames ({}) ", app.frames.len());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.frame_list_state);
}
