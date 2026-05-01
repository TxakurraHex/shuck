use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem},
};

use crate::app::{App, Pane, TreeRow};
use crate::model::Layer;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app.tree_rows();

    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match row {
            TreeRow::LayerHeader {
                depth,
                name,
                summary,
                ..
            } => {
                let indent = "  ".repeat(*depth);
                ListItem::new(format!("{indent}▼ {name}  -- {summary}")).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            }
            TreeRow::Field {
                depth,
                layer_path,
                field_index,
            } => {
                let indent = "  ".repeat(*depth);
                let label =
                    field_label(app, layer_path, *field_index).unwrap_or_else(|| "?".into());
                ListItem::new(format!("{indent}{label}"))
            }
        })
        .collect();

    let border_style = if app.focus == Pane::Tree {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let title = " Layers (Tab to focus, j/k to move) ";
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.tree_state);

    // let block = Block::default().borders(Borders::ALL).title(" Layers ");
    // let body = Paragraph::new("(dissection lands in Phase 1)").block(block);
    // f.render_widget(body, area);
}

fn field_label(app: &App, layer_path: &[usize], field_index: usize) -> Option<String> {
    let frame = app.selected_frame()?;
    let layer = walk_path(&frame.layers, layer_path)?;
    let field = layer.fields.get(field_index)?;
    Some(format!("{}: {}", field.name, field.value))
}

fn walk_path<'a>(layers: &'a [Layer], path: &[usize]) -> Option<&'a Layer> {
    let (first, rest) = path.split_first()?;
    let mut current = layers.get(*first)?;
    for idx in rest {
        current = current.children.get(*idx)?;
    }
    Some(current)
}
