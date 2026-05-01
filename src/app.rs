use crate::model::{Frame, Layer};
use ratatui::widgets::ListState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    FrameList,
    Tree,
}

/// One row in the rendered tree. Either a layer header or a field beneath it.
#[derive(Debug, Clone)]
pub enum TreeRow {
    /// (path of layer indices into the frame's layer tree, depth, name, summary)
    LayerHeader {
        path: Vec<usize>,
        depth: usize,
        name: String,
        summary: String,
    },
    /// (depth, layer-path, field index within that layer)
    Field {
        depth: usize,
        layer_path: Vec<usize>,
        field_index: usize,
    },
}

pub struct App {
    pub frames: Vec<Frame>,
    pub frame_list_state: ListState,
    pub tree_state: ListState,
    pub focus: Pane,
}

impl App {
    pub fn new(frames: Vec<Frame>) -> Self {
        let mut frame_list_state = ListState::default();
        frame_list_state.select(Some(0));
        let mut tree_state = ListState::default();
        tree_state.select(Some(0));
        Self {
            frames,
            frame_list_state,
            tree_state,
            focus: Pane::FrameList,
        }
    }

    pub fn selected_index(&self) -> usize {
        self.frame_list_state.selected().unwrap_or(0)
    }

    pub fn selected_frame(&self) -> Option<&Frame> {
        self.frames.get(self.selected_index())
    }

    pub fn next_frame(&mut self) {
        if self.frames.is_empty() {
            return;
        }
        let next = (self.selected_index() + 1).min(self.frames.len() - 1);
        self.frame_list_state.select(Some(next));
        self.tree_state.select(Some(0));
    }

    pub fn previous_frame(&mut self) {
        let prev = self.selected_index().saturating_sub(1);
        self.frame_list_state.select(Some(prev));
        self.tree_state.select(Some(0));
    }

    pub fn first_frame(&mut self) {
        self.frame_list_state.select(Some(0));
        self.tree_state.select(Some(0));
    }

    pub fn last_frame(&mut self) {
        if !self.frames.is_empty() {
            self.frame_list_state.select(Some(self.frames.len() - 1));
            self.tree_state.select(Some(0));
        }
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Pane::FrameList => Pane::Tree,
            Pane::Tree => Pane::FrameList,
        };
    }

    /// Flatten selected frame's layer tree into better displayable rows.
    /// Recomputed each draw cycle (cheap and avoids need for invalidation, plus I'm lazy).
    pub fn tree_rows(&self) -> Vec<TreeRow> {
        let Some(frame) = self.selected_frame() else {
            return vec![];
        };
        let mut rows = Vec::new();
        for (i, layer) in frame.layers.iter().enumerate() {
            walk(layer, vec![i], 0, &mut rows);
        }
        rows
    }

    pub fn next_tree_row(&mut self) {
        let len = self.tree_rows().len();
        if len == 0 {
            return;
        }
        let cur = self.tree_state.selected().unwrap_or(0);
        self.tree_state.select(Some((cur + 1).min(len - 1)));
    }

    pub fn previous_tree_row(&mut self) {
        let cur = self.tree_state.selected().unwrap_or(0);
        self.tree_state.select(Some(cur.saturating_sub(1)));
    }

    /// Returns (offset, length) in the current frame's raw bytes that
    /// correspond to the selected tree row, if any. Layer headers report
    /// the span covering all fields.
    pub fn highlight_range(&self) -> Option<(usize, usize)> {
        let frame = self.selected_frame()?;
        let rows = self.tree_rows();
        let row = rows.get(self.tree_state.selected().unwrap_or(0))?;
        match row {
            TreeRow::Field {
                layer_path,
                field_index,
                ..
            } => {
                let layer = layer_at(&frame.layers, layer_path)?;
                let f = layer.fields.get(*field_index)?;
                Some((f.offset, f.length))
            }
            TreeRow::LayerHeader { path, .. } => {
                let layer = layer_at(&frame.layers, path)?;
                let first = layer.fields.first()?;
                let last = layer.fields.last()?;
                let start = first.offset;
                let end = last.offset + last.length;
                Some((start, end - start))
            }
        }
    }
}

/// Walk the currently selected layers children until none are left, flattening
/// each layer into a header and set of field rows.
fn walk(layer: &Layer, path: Vec<usize>, depth: usize, out: &mut Vec<TreeRow>) {
    out.push(TreeRow::LayerHeader {
        path: path.clone(),
        depth,
        name: layer.name.clone(),
        summary: layer.summary.clone(),
    });
    for (fi, _) in layer.fields.iter().enumerate() {
        out.push(TreeRow::Field {
            depth: depth + 1,
            layer_path: path.clone(),
            field_index: fi,
        });
    }
    for (ci, child) in layer.children.iter().enumerate() {
        let mut child_path = path.clone();
        child_path.push(ci);
        walk(child, child_path, depth + 1, out);
    }
}

fn layer_at<'a>(layers: &'a [Layer], path: &[usize]) -> Option<&'a Layer> {
    let (first, rest) = path.split_first()?;
    let mut current = layers.get(*first)?;
    for idx in rest {
        current = current.children.get(*idx)?;
    }
    Some(current)
}
