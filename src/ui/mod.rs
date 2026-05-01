use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
};

use crate::app::App;

mod frame_list;
mod hex;
mod tree;

pub fn draw(f: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(f.area());

    frame_list::draw(f, app, outer[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);

    tree::draw(f, app, bottom[0]);
    hex::draw(f, app, bottom[1]);
}
