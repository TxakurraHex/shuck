use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let title = match app.selected_frame() {
        Some(fr) => format!(" Hex - frame #{} ({} bytes)", fr.number, fr.raw.len()),
        None => " Hex ".to_string(),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let body = match app.selected_frame() {
        Some(fr) => {
            let highlight = app.highlight_range();
            format_hex(&fr.raw, highlight)
        }
        None => vec![],
    };
    f.render_widget(Paragraph::new(body).block(block), area);
}

fn format_hex(bytes: &[u8], highlight: Option<(usize, usize)>) -> Vec<Line<'static>> {
    let hl = highlight.map(|(o, l)| (o, o + l));
    let in_hl = |i: usize| hl.map_or(false, |(s, e)| i >= s && i < e);

    let highlight_style = Style::default()
        .fg(Color::Black)
        .bg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let mut lines = Vec::new();
    for (chunk_idx, chunk) in bytes.chunks(16).enumerate() {
        let row_offset = chunk_idx * 16;
        let mut spans: Vec<Span<'static>> = Vec::new();

        spans.push(Span::raw(format!("{:04x}  ", row_offset)));

        // Hex bytes
        for (i, b) in chunk.iter().enumerate() {
            let abs = row_offset + i;
            let style = if in_hl(abs) {
                highlight_style
            } else {
                Style::default()
            };
            spans.push(Span::styled(format!("{:02x}", b), style));
            spans.push(Span::raw(" "));
        }
        // Pad short last line so ASCII gutter aligns
        for _ in chunk.len()..16 {
            spans.push(Span::raw("  "));
        }

        spans.push(Span::raw(" "));

        // ASCII gutter
        for (i, b) in chunk.iter().enumerate() {
            let abs = row_offset + i;
            let ch = if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            };
            let style = if in_hl(abs) {
                highlight_style
            } else {
                Style::default()
            };
            spans.push(Span::styled(ch.to_string(), style));
        }

        lines.push(Line::from(spans));
    }
    lines
}
