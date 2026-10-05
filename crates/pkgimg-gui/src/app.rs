use crate::model::Model;
use egui::{Color32, RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use pkgimg_core::analysis::{Group, SectionSel};
use pkgimg_core::inspect::{self, FieldValue};
use pkgimg_core::{Obj, Val};
use std::collections::HashMap;
use std::sync::mpsc;

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    Heap,
    Objects,
    Compiled,
    Methods,
    Sources,
    Deps,
}

const TABS: [(Tab, &str); 7] = [
    (Tab::Overview, "Overview"),
    (Tab::Heap, "Heap"),
    (Tab::Objects, "Objects"),
    (Tab::Compiled, "Code instances"),
    (Tab::Methods, "Methods"),
    (Tab::Sources, "Sources"),
    (Tab::Deps, "Dependencies"),
];

pub enum Load {
    /// Native: paths to open (first is the target), and an optional system image.
    Paths(Vec<std::path::PathBuf>, Option<std::path::PathBuf>),
    /// Web: in-memory files `(name, bytes)`.
    Bytes(Vec<(String, Vec<u8>)>),
}

enum State {
    Empty,
    Loading(mpsc::Receiver<Result<Model, String>>, String),
    Ready(Box<Model>),
    Failed(String),
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum CiGroup {
    None,
    Method,
    File,
    Module,
    Root,
    Parent,
}

fn ci_group_key(c: &pkgimg_core::analysis::CiRow, g: CiGroup) -> String {
    match g {
        CiGroup::None => String::new(),
        CiGroup::Method => format!("{}.{} @ {}:{}", c.module, c.method, c.file.rsplit('/').next().unwrap_or(""), c.line),
        CiGroup::File => c.file.clone(),
        CiGroup::Module => c.module.clone(),
        CiGroup::Root => c.root.clone().unwrap_or_else(|| "<no provenance record>".into()),
        CiGroup::Parent => c.parent.clone().unwrap_or_else(|| if c.root.is_some() { "<entry point>".into() } else { "<no provenance record>".into() }),
    }
}

#[derive(Default)]
struct Sorted {
    col: usize,
    desc: bool,
    order: Vec<usize>,
    /// Inputs the order was computed for; recompute when they change.
    key: String,
}

pub struct App {
    state: State,
    tab: Tab,
    path_input: String,
    sysimage_input: String,
    // heap view
    heap_group: Group,
    heap_section: SectionSel,
    heap_filter: String,
    heap_sort: Sorted,
    // objects view
    obj_filter: String,
    obj_exact: Option<u32>,
    obj_rows: Sorted,
    // code instances
    ci_filter: String,
    ci_group: CiGroup,
    ci_group_sel: Option<String>,
    ci_groups: Sorted,
    ci_sort: Sorted,
    // methods
    m_filter: String,
    m_sort: Sorted,
    // sources
    src_sel: usize,
    src_scroll_line: Option<usize>,
    // inspector
    history: Vec<Obj>,
    hist_pos: usize,
    referrers: Option<(Obj, Vec<(usize, String)>)>,
    show_hex: bool,
    #[cfg(not(target_arch = "wasm32"))]
    browser: crate::browser::Browser,
    show_browser: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, initial: Option<Load>) -> App {
        cc.egui_ctx.options_mut(|o| o.zoom_with_keyboard = true);
        let mut app = App {
            state: State::Empty,
            tab: Tab::Overview,
            path_input: String::new(),
            sysimage_input: String::new(),
            heap_group: Group::Type,
            heap_section: SectionSel::All,
            heap_filter: String::new(),
            heap_sort: Sorted { col: 2, desc: true, ..Default::default() },
            obj_filter: String::new(),
            obj_exact: None,
            obj_rows: Sorted::default(),
            ci_filter: String::new(),
            ci_group: CiGroup::None,
            ci_group_sel: None,
            ci_groups: Sorted { col: 2, desc: true, ..Default::default() },
            ci_sort: Sorted { col: 0, desc: true, ..Default::default() },
            m_filter: String::new(),
            m_sort: Sorted::default(),
            src_sel: 0,
            src_scroll_line: None,
            history: vec![],
            hist_pos: 0,
            referrers: None,
            show_hex: false,
            #[cfg(not(target_arch = "wasm32"))]
            browser: crate::browser::Browser::new(),
            show_browser: false,
        };
        if let Some(l) = initial {
            app.start_load(&cc.egui_ctx, l);
        }
        #[cfg(target_arch = "wasm32")]
        if let Some(urls) = web::load_param() {
            app.start_fetch(&cc.egui_ctx, urls);
        }
        app
    }

    /// Web: fetch `urls` and load them as dropped files.
    #[cfg(target_arch = "wasm32")]
    fn start_fetch(&mut self, ctx: &egui::Context, urls: Vec<String>) {
        let (tx, rx) = mpsc::channel();
        let ctx2 = ctx.clone();
        let label = urls.join(", ");
        wasm_bindgen_futures::spawn_local(async move {
            let mut files = vec![];
            for u in urls {
                match web::fetch_bytes(&u).await {
                    Ok(b) => files.push((u.rsplit('/').next().unwrap_or(&u).to_string(), b)),
                    Err(e) => {
                        let _ = tx.send(Err(format!("{u}: {e}")));
                        ctx2.request_repaint();
                        return;
                    }
                }
            }
            let _ = tx.send(crate::load(Load::Bytes(files)).map_err(|e| format!("{e:#}")));
            ctx2.request_repaint();
        });
        self.state = State::Loading(rx, label);
    }

    fn start_load(&mut self, ctx: &egui::Context, load: Load) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Load::Paths(p, _) = &load
            && let Some(first) = p.first()
        {
            let abs = std::fs::canonicalize(first).unwrap_or_else(|_| first.clone());
            self.browser.remember(&abs);
        }
        self.show_browser = false;
        let (tx, rx) = mpsc::channel();
        let label = match &load {
            Load::Paths(p, _) => p.first().map(|p| p.display().to_string()).unwrap_or_default(),
            Load::Bytes(b) => b.first().map(|b| b.0.clone()).unwrap_or_default(),
        };
        let ctx2 = ctx.clone();
        let job = move || {
            let r = crate::load(load).map_err(|e| format!("{e:#}"));
            let _ = tx.send(r);
            ctx2.request_repaint();
        };
        #[cfg(not(target_arch = "wasm32"))]
        std::thread::spawn(job);
        #[cfg(target_arch = "wasm32")]
        job();
        self.state = State::Loading(rx, label);
        self.history.clear();
        self.hist_pos = 0;
        self.referrers = None;
        for s in [&mut self.heap_sort, &mut self.obj_rows, &mut self.ci_sort, &mut self.m_sort] {
            s.key.clear();
        }
    }

    fn select(&mut self, o: Obj) {
        if self.history.get(self.hist_pos.wrapping_sub(1)) == Some(&o) {
            return;
        }
        self.history.truncate(self.hist_pos);
        self.history.push(o);
        self.hist_pos = self.history.len();
        self.referrers = None;
    }

    #[cfg(test)]
    pub fn browser_mut(&mut self) -> &mut crate::browser::Browser {
        &mut self.browser
    }

    #[cfg(test)]
    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }

    /// Select the code instance with the most native code (screenshot tests).
    #[cfg(test)]
    pub fn select_largest_ci(&mut self) {
        let State::Ready(m) = &self.state else { return };
        if let Some(c) = m.cis.iter().max_by_key(|c| c.native_bytes) {
            let o = c.obj;
            self.select(o);
        }
    }

    fn selected(&self) -> Option<Obj> {
        self.hist_pos.checked_sub(1).and_then(|i| self.history.get(i)).copied()
    }
}

fn bar_color(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode { Color32::from_hex("#3987e5").unwrap() } else { Color32::from_hex("#2a78d6").unwrap() }
}

const CATEGORICAL_LIGHT: [&str; 8] = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];
const CATEGORICAL_DARK: [&str; 8] = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];

fn categorical(ui: &Ui, i: usize) -> Color32 {
    let p = if ui.visuals().dark_mode { CATEGORICAL_DARK } else { CATEGORICAL_LIGHT };
    Color32::from_hex(p[i % 8]).unwrap()
}

fn human(b: u64) -> String {
    match b {
        b if b >= 10 << 20 => format!("{:.1} MiB", b as f64 / (1 << 20) as f64),
        b if b >= 10 << 10 => format!("{:.1} KiB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

/// A horizontal data bar filling `frac` of the available width.
fn data_bar(ui: &mut Ui, frac: f32, color: Color32) {
    let w = ui.available_width().max(1.0);
    let h = 10.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, h), Sense::hover());
    let mut r = rect;
    r.set_width((w * frac.clamp(0.0, 1.0)).max(if frac > 0.0 { 2.0 } else { 0.0 }));
    ui.painter().rect_filled(r, 2.0, color);
}

/// Sortable header cell.
fn sort_header(ui: &mut Ui, label: &str, i: usize, s: &mut Sorted, default_desc: bool) {
    let arrow = if s.col == i { if s.desc { " ⏷" } else { " ⏶" } } else { "" };
    if ui.add(egui::Button::new(RichText::new(format!("{label}{arrow}")).strong()).frame(false)).clicked() {
        if s.col == i {
            s.desc = !s.desc;
        } else {
            s.col = i;
            s.desc = default_desc;
        }
        s.key.clear();
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Dropped files
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let paths: Vec<_> = dropped.iter().map(|f| f.path().to_path_buf()).collect();
                self.start_load(&ctx, Load::Paths(paths, None));
            }
            #[cfg(target_arch = "wasm32")]
            {
                // Browsers read files asynchronously: read everything, then load.
                let (tx, rx) = mpsc::channel();
                let ctx2 = ctx.clone();
                let label = dropped.first().map(|f| f.path().display().to_string()).unwrap_or_default();
                wasm_bindgen_futures::spawn_local(async move {
                    let mut files = vec![];
                    for f in &dropped {
                        match f.bytes_async().await {
                            Ok(b) => files.push((f.path().display().to_string(), b)),
                            Err(e) => {
                                let _ = tx.send(Err(e));
                                ctx2.request_repaint();
                                return;
                            }
                        }
                    }
                    let _ = tx.send(crate::load(Load::Bytes(files)).map_err(|e| format!("{e:#}")));
                    ctx2.request_repaint();
                });
                self.state = State::Loading(rx, label);
                self.history.clear();
                self.hist_pos = 0;
            }
        }
        if let State::Loading(rx, _) = &self.state
            && let Ok(r) = rx.try_recv()
        {
            self.state = match r {
                Ok(m) => State::Ready(Box::new(m)),
                Err(e) => State::Failed(e),
            };
        }
        // Back/forward with mouse buttons or alt+arrows
        let (back, fwd) = ctx.input(|i| {
            (
                i.pointer.button_pressed(egui::PointerButton::Extra1) || (i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft)),
                i.pointer.button_pressed(egui::PointerButton::Extra2) || (i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight)),
            )
        });
        if back && self.hist_pos > 1 {
            self.hist_pos -= 1;
            self.referrers = None;
        }
        if fwd && self.hist_pos < self.history.len() {
            self.hist_pos += 1;
            self.referrers = None;
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("pkgimg");
                #[cfg(not(target_arch = "wasm32"))]
                if matches!(self.state, State::Ready(_))
                    && ui.selectable_label(self.show_browser, "📂 Open…").on_hover_text("browse cache files (ctrl+o)").clicked()
                {
                    self.show_browser = !self.show_browser;
                }
                ui.separator();
                if let State::Ready(m) = &self.state {
                    let im = m.w.target();
                    ui.label(RichText::new(im.display_name()).strong());
                    ui.label(RichText::new(format!("{}  ·  Julia {}  ·  loaded in {:.0?}", im.path.display(), im.header.base.julia_version, m.load_time)).weak());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::widgets::global_theme_preference_switch(ui);
                });
            });
            let mut reload = None;
            if let State::Ready(m) = &self.state
                && (m.w.sysimg.is_none() || !m.w.missing.is_empty())
            {
                ui.horizontal(|ui| {
                    let msg = if m.w.sysimg.is_none() {
                        "No matching system image found: types and methods defined outside this package cannot be decoded.".to_string()
                    } else {
                        format!("Dependencies not found: {}", m.w.missing.iter().map(|d| d.name.as_str()).collect::<Vec<_>>().join(", "))
                    };
                    ui.colored_label(ui.visuals().warn_fg_color, msg);
                    #[cfg(not(target_arch = "wasm32"))]
                    if m.w.sysimg.is_none() {
                        ui.add(egui::TextEdit::singleline(&mut self.sysimage_input).hint_text("path to sys.so").desired_width(320.0));
                        if ui.button("Reload").clicked() && !self.sysimage_input.is_empty() {
                            reload = Some(Load::Paths(vec![m.w.target().path.clone()], Some(shellexpand(&self.sysimage_input))));
                        }
                    }
                    #[cfg(target_arch = "wasm32")]
                    ui.label("Drop the matching sys.so together with the .ji/.so.");
                });
            }
            if let Some(l) = reload {
                let ctx = ui.ctx().clone();
                self.start_load(&ctx, l);
            }
            if matches!(self.state, State::Ready(_)) {
                ui.horizontal(|ui| {
                    for (t, name) in TABS {
                        if ui.selectable_label(self.tab == t, name).clicked() {
                            self.tab = t;
                        }
                    }
                });
            }
        });

        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::O)) {
            self.show_browser = !self.show_browser;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if self.show_browser || matches!(self.state, State::Empty | State::Failed(_)) {
            let mut pick = None;
            egui::CentralPanel::default().show(ui, |ui| {
                if let State::Failed(e) = &self.state {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
                pick = self.browser.ui(ui);
            });
            if let Some(p) = pick {
                self.start_load(&ctx, Load::Paths(vec![p.ji], p.sysimage));
            }
            return;
        }
        let state = std::mem::replace(&mut self.state, State::Empty);
        let state = match state {
            State::Ready(mut m) => {
                if self.selected().is_some() {
                    egui::Panel::right("inspector").resizable(true).default_size(480.0).max_size(900.0).show(ui, |ui| {
                        self.inspector(ui, &m);
                    });
                }
                egui::CentralPanel::default().show(ui, |ui| match self.tab {
                    Tab::Overview => self.overview(ui, &mut m),
                    Tab::Heap => self.heap(ui, &mut m),
                    Tab::Objects => self.objects(ui, &m),
                    Tab::Compiled => self.compiled(ui, &m),
                    Tab::Methods => self.methods(ui, &m),
                    Tab::Sources => self.sources(ui, &m),
                    Tab::Deps => self.deps(ui, &m),
                });
                State::Ready(m)
            }
            s => {
                egui::CentralPanel::default().show(ui, |ui| self.welcome(ui, &s));
                s
            }
        };
        if matches!(self.state, State::Empty) {
            self.state = state;
        }
    }
}

impl App {
    fn welcome(&mut self, ui: &mut Ui, s: &State) {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            match s {
                State::Loading(_, label) => {
                    ui.spinner();
                    ui.label(format!("Loading {label} …"));
                    return;
                }
                State::Failed(e) => {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                    ui.add_space(12.0);
                }
                _ => {}
            }
            ui.heading("Open a package image");
            ui.label("Drop a .ji (with its .so next to it) here, or enter a path.");
            #[cfg(target_arch = "wasm32")]
            ui.label("In the browser, drop the .ji and .so together, plus sys.so and dependency .ji files to resolve names.");
            #[cfg(target_arch = "wasm32")]
            ui.label(RichText::new("Or open this page with ?load=url1,url2,… to fetch them.").weak());
            #[cfg(not(target_arch = "wasm32"))]
            ui.horizontal(|ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut self.path_input).hint_text("~/.julia/compiled/v1.14/Pkg/xxxx.ji").desired_width(480.0));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button("Open").clicked() || enter) && !self.path_input.is_empty() {
                    let p = shellexpand(&self.path_input);
                    let ctx = ui.ctx().clone();
                    self.start_load(&ctx, Load::Paths(vec![p], None));
                }
            });
        });
    }

    fn overview(&mut self, ui: &mut Ui, m: &mut Model) {
        let rows: Vec<_> = m.hist(Group::Type, SectionSel::All).iter().take(20).cloned().collect();
        let m: &Model = m;
        let im = m.w.target();
        let st = &m.stats;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.columns(2, |cols| {
                let ui = &mut cols[0];
                ui.heading("Image");
                egui::Grid::new("facts").num_columns(2).striped(true).show(ui, |ui| {
                    let mut row = |k: &str, v: String| {
                        ui.label(RichText::new(k).weak());
                        ui.label(v);
                        ui.end_row();
                    };
                    let h = &im.header;
                    row("modules", im.display_name());
                    row("julia", format!("{} ({})", h.base.julia_version, h.base.git_commit.as_deref().unwrap_or("-")));
                    row("format", format!("v{}", h.base.format_version));
                    if let Some(p) = &h.pkg {
                        let f = &p.cache_flags;
                        row("flags", format!("opt={} debug={} check_bounds={} inline={}", f.opt_level, f.debug_level, f.check_bounds, f.inline));
                        row("dependencies", format!("{} ({} unresolved)", p.required_modules.len(), m.w.missing.len()));
                        row("include files", p.includes.len().to_string());
                    }
                    row(".ji size", human(im.ji.len() as u64));
                    if let Some(n) = &im.native {
                        row("native size", format!("{}  (.text {})", human(n.file_size), human(n.text_size)));
                        row("native functions", n.fvars.len().to_string());
                    }
                    row("objects", format!("{} + {} const", m.objs.len(), m.cst.len()));
                    row("methods", st.n_methods.to_string());
                    row("method instances", st.n_mi.to_string());
                    row("code instances", format!("{}  ({} native, {} external, {} dead)", m.cis.len(), st.native_cis, st.ext_cis, st.dead_cis));
                    row("native code (CIs)", human(st.native_bytes));
                    row("inferred IR", human(st.inferred_bytes));
                    if st.untyped > 0 {
                        row("untyped objects", st.untyped.to_string());
                    }
                });
                let ui = &mut cols[1];
                ui.heading("Heap sections");
                let s = &im.heap.sizes;
                let secs = [
                    ("objects", s.objects), ("const_data", s.const_data), ("relocs", s.relocs),
                    ("symbols", s.symbols), ("gvar_record", s.gvar_record), ("fptr_record", s.fptr_record),
                ];
                let total: u64 = secs.iter().map(|x| x.1 as u64).sum::<u64>().max(1);
                let w = ui.available_width();
                let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 18.0), Sense::hover());
                let mut x = rect.left();
                for (i, (_, b)) in secs.iter().enumerate() {
                    let bw = w * (*b as f32 / total as f32);
                    if bw >= 1.0 {
                        let r = egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2((bw - 2.0).max(1.0), rect.height()));
                        ui.painter().rect_filled(r, 2.0, categorical(ui, i));
                    }
                    x += bw;
                }
                ui.add_space(4.0);
                egui::Grid::new("secs").num_columns(3).show(ui, |ui| {
                    for (i, (name, b)) in secs.iter().enumerate() {
                        let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
                        ui.painter().rect_filled(r, 2.0, categorical(ui, i));
                        ui.label(*name);
                        ui.label(RichText::new(human(*b as u64)).monospace());
                        ui.end_row();
                    }
                });
            });
            ui.add_space(12.0);
            ui.heading("Largest types");
            let max = rows.first().map_or(1, |r| r.bytes).max(1);
            let color = bar_color(ui);
            let mut clicked = None;
            egui::Grid::new("types").num_columns(4).striped(true).show(ui, |ui| {
                for r in &rows {
                    if ui.link(&r.key).clicked() {
                        clicked = Some(r.key.clone());
                    }
                    ui.label(RichText::new(human(r.bytes)).monospace());
                    ui.label(RichText::new(r.count.to_string()).monospace().weak());
                    ui.allocate_ui(egui::vec2(260.0, 12.0), |ui| data_bar(ui, r.bytes as f32 / max as f32, color));
                    ui.end_row();
                }
            });
            if let Some(k) = clicked {
                self.show_type(m, &k);
            }
        });
    }

    fn show_type(&mut self, m: &Model, key: &str) {
        self.obj_exact = m.keys.iter().position(|k| k == key).map(|i| i as u32);
        self.obj_filter.clear();
        self.obj_rows.key.clear();
        self.tab = Tab::Objects;
    }

    fn heap(&mut self, ui: &mut Ui, m: &mut Model) {
        ui.horizontal(|ui| {
            ui.label("Group by");
            for (g, name) in [(Group::Type, "type"), (Group::FullType, "full type"), (Group::Referrer, "referrer"), (Group::Section, "section")] {
                if ui.selectable_label(self.heap_group == g, name).clicked() {
                    self.heap_group = g;
                }
            }
            ui.separator();
            for (s, name) in [(SectionSel::All, "all"), (SectionSel::Objects, "objects"), (SectionSel::Const, "const data")] {
                if ui.selectable_label(self.heap_section == s, name).clicked() {
                    self.heap_section = s;
                }
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.heap_filter).hint_text("filter").desired_width(220.0));
        });
        let (g, s) = (self.heap_group, self.heap_section);
        let rows = m.hist(g, s).clone();
        let key = format!("{:?}{:?}{}{}{}", g, s, self.heap_filter, self.heap_sort.col, self.heap_sort.desc);
        if self.heap_sort.key != key {
            let f = self.heap_filter.to_lowercase();
            let mut order: Vec<usize> = (0..rows.len()).filter(|&i| f.is_empty() || rows[i].key.to_lowercase().contains(&f)).collect();
            let sc = self.heap_sort.col;
            order.sort_by(|&a, &b| {
                let (x, y) = (&rows[a], &rows[b]);
                match sc {
                    0 => x.key.cmp(&y.key),
                    1 => x.count.cmp(&y.count),
                    _ => x.bytes.cmp(&y.bytes),
                }
            });
            if self.heap_sort.desc {
                order.reverse();
            }
            self.heap_sort.order = order;
            self.heap_sort.key = key;
        }
        let total: u64 = rows.iter().map(|r| r.bytes).sum::<u64>().max(1);
        let max = rows.iter().map(|r| r.bytes).max().unwrap_or(1).max(1);
        ui.label(RichText::new(format!("{} groups, {} total", self.heap_sort.order.len(), human(total))).weak());
        let color = bar_color(ui);
        let mut clicked = None;
        let mut sort = std::mem::take(&mut self.heap_sort);
        let order = sort.order.clone();
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::remainder().at_least(300.0).clip(true).resizable(true))
            .column(Column::exact(90.0))
            .column(Column::exact(100.0))
            .column(Column::exact(60.0))
            .column(Column::exact(180.0))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "group", 0, &mut sort, false));
                h.col(|ui| sort_header(ui, "count", 1, &mut sort, true));
                h.col(|ui| sort_header(ui, "bytes", 2, &mut sort, true));
                h.col(|ui| { ui.strong("%"); });
                h.col(|_| {});
            })
            .body(|body| {
                body.rows(18.0, order.len(), |mut row| {
                    let r = &rows[order[row.index()]];
                    row.col(|ui| { ui.label(&r.key); });
                    row.col(|ui| { ui.label(RichText::new(r.count.to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(human(r.bytes)).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(format!("{:.1}", 100.0 * r.bytes as f64 / total as f64)).monospace().weak()); });
                    row.col(|ui| data_bar(ui, r.bytes as f32 / max as f32, color));
                    if row.response().clicked() {
                        clicked = Some(r.key.clone());
                    }
                });
            });
        self.heap_sort = sort;
        if let Some(k) = clicked {
            // Groups map onto type keys for type grouping; otherwise filter by the type part.
            let ty = k.split(" <- ").next().unwrap_or(&k).trim_end_matches(" (element data)").to_string();
            if self.heap_group == Group::FullType {
                self.obj_exact = None;
                self.obj_filter = k;
                self.obj_rows.key.clear();
                self.tab = Tab::Objects;
            } else {
                self.show_type(m, &ty);
            }
        }
    }

    fn objects(&mut self, ui: &mut Ui, m: &Model) {
        ui.horizontal(|ui| {
            if let Some(k) = self.obj_exact {
                ui.label("type =");
                ui.strong(&m.keys[k as usize]);
                if ui.small_button("✕").clicked() {
                    self.obj_exact = None;
                    self.obj_rows.key.clear();
                }
                ui.separator();
            }
            if ui.add(egui::TextEdit::singleline(&mut self.obj_filter).hint_text("filter by value (substring)").desired_width(280.0)).changed() {
                self.obj_rows.key.clear();
            }
        });
        let key = format!("{:?}{}{}{}", self.obj_exact, self.obj_filter, self.obj_rows.col, self.obj_rows.desc);
        if self.obj_rows.key != key {
            let f = self.obj_filter.to_lowercase();
            let mut order: Vec<usize> = (0..m.n_entries())
                .filter(|&i| self.obj_exact.is_none_or(|k| m.obj_key[i] == k))
                .filter(|&i| f.is_empty() || m.w.show(Val::Obj(m.entry(i).obj), 3).to_lowercase().contains(&f))
                .collect();
            if self.obj_rows.col == 1 {
                order.sort_by_key(|&i| m.entry(i).size);
            }
            if self.obj_rows.desc {
                order.reverse();
            }
            self.obj_rows.order = order;
            self.obj_rows.key = key;
        }
        let n = self.obj_rows.order.len();
        let bytes: u64 = self.obj_rows.order.iter().map(|&i| m.entry(i).size as u64).sum();
        ui.label(RichText::new(format!("{n} objects, {}", human(bytes))).weak());
        let mut clicked = None;
        let mut sort = std::mem::take(&mut self.obj_rows);
        let order = sort.order.clone();
        let sel = self.selected();
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::exact(130.0))
            .column(Column::exact(80.0))
            .column(Column::initial(220.0).clip(true).resizable(true))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "offset", 0, &mut sort, false));
                h.col(|ui| sort_header(ui, "size", 1, &mut sort, true));
                h.col(|ui| { ui.strong("type"); });
                h.col(|ui| { ui.strong("value"); });
            })
            .body(|body| {
                body.rows(18.0, n, |mut row| {
                    let i = order[row.index()];
                    let e = m.entry(i);
                    row.set_selected(sel == Some(e.obj));
                    row.col(|ui| { ui.label(RichText::new(format!("{}{}", if e.obj.cst { "c+" } else { "" }, e.obj.off)).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(e.size.to_string()).monospace()); });
                    row.col(|ui| { ui.label(&m.keys[m.obj_key[i] as usize]); });
                    row.col(|ui| { ui.label(m.w.show(Val::Obj(e.obj), 3)); });
                    if row.response().clicked() {
                        clicked = Some(e.obj);
                    }
                });
            });
        self.obj_rows = sort;
        if let Some(o) = clicked {
            self.select(o);
        }
    }

    fn compiled(&mut self, ui: &mut Ui, m: &Model) {
        ui.horizontal(|ui| {
            ui.label("Group by");
            let has_prov = m.provenance_path.is_some();
            for (g, name, enabled) in [(CiGroup::None, "none", true), (CiGroup::Method, "method", true), (CiGroup::File, "file", true), (CiGroup::Module, "module", true), (CiGroup::Root, "root", has_prov), (CiGroup::Parent, "parent", has_prov)] {
                let r = ui.add_enabled(enabled, egui::Button::selectable(self.ci_group == g, name));
                let r = if enabled { r } else { r.on_disabled_hover_text("needs a provenance sidecar (JULIA_IMAGE_PROVENANCE)") };
                if r.clicked() {
                    self.ci_group = g;
                    self.ci_group_sel = None;
                    self.ci_groups.key.clear();
                    self.ci_sort.key.clear();
                }
            }
            if let Some(p) = &m.provenance_path {
                ui.label(RichText::new("provenance ✔").weak()).on_hover_text(p);
            }
        });
        if self.ci_group != CiGroup::None && self.ci_group_sel.is_none() {
            self.ci_group_table(ui, m);
            return;
        }
        if let Some(sel) = self.ci_group_sel.clone() {
            ui.horizontal(|ui| {
                ui.label(format!("{:?} =", self.ci_group).to_lowercase());
                ui.strong(&sel);
                if ui.small_button("✕").clicked() {
                    self.ci_group_sel = None;
                    self.ci_sort.key.clear();
                }
            });
        }
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.ci_filter).hint_text("filter (method, module, file, signature)").desired_width(360.0));
            let total: u64 = m.stats.native_bytes;
            ui.label(RichText::new(format!("{} code instances, {} native, {} inferred IR", m.cis.len(), human(total), human(m.stats.inferred_bytes))).weak());
        });
        let key = format!("{}{}{}{:?}", self.ci_filter, self.ci_sort.col, self.ci_sort.desc, self.ci_group_sel);
        if self.ci_sort.key != key {
            let f = self.ci_filter.to_lowercase();
            let (g, gsel) = (self.ci_group, self.ci_group_sel.clone());
            let mut order: Vec<usize> = (0..m.cis.len())
                .filter(|&i| {
                    let c = &m.cis[i];
                    gsel.as_ref().is_none_or(|s| ci_group_key(c, g) == *s)
                        && (f.is_empty() || [&c.method, &c.module, &c.file, &c.spec].iter().any(|s| s.to_lowercase().contains(&f)))
                })
                .collect();
            let sc = self.ci_sort.col;
            order.sort_by(|&a, &b| {
                let (x, y) = (&m.cis[a], &m.cis[b]);
                match sc {
                    0 => (x.native_bytes + x.wrapper_bytes).cmp(&(y.native_bytes + y.wrapper_bytes)),
                    1 => x.inferred_bytes.cmp(&y.inferred_bytes),
                    2 => x.infer_self_ms.total_cmp(&y.infer_self_ms),
                    3 => x.status.cmp(&y.status),
                    4 => x.invoke.cmp(&y.invoke),
                    _ => (&x.module, &x.method, &x.spec).cmp(&(&y.module, &y.method, &y.spec)),
                }
            });
            if self.ci_sort.desc {
                order.reverse();
            }
            self.ci_sort.order = order;
            self.ci_sort.key = key;
        }
        let mut sort = std::mem::take(&mut self.ci_sort);
        let order = sort.order.clone();
        let sel = self.selected();
        let mut clicked = None;
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::exact(70.0))
            .column(Column::exact(70.0))
            .column(Column::exact(70.0))
            .column(Column::exact(50.0))
            .column(Column::exact(80.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "native", 0, &mut sort, true));
                h.col(|ui| sort_header(ui, "inferred", 1, &mut sort, true));
                h.col(|ui| sort_header(ui, "infer ms", 2, &mut sort, true));
                h.col(|ui| sort_header(ui, "status", 3, &mut sort, false));
                h.col(|ui| sort_header(ui, "invoke", 4, &mut sort, false));
                h.col(|ui| sort_header(ui, "specialization", 5, &mut sort, false));
            })
            .body(|body| {
                body.rows(18.0, order.len(), |mut row| {
                    let c = &m.cis[order[row.index()]];
                    row.set_selected(sel == Some(c.obj));
                    row.col(|ui| { ui.label(RichText::new((c.native_bytes + c.wrapper_bytes).to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(c.inferred_bytes.to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(format!("{:.2}", c.infer_self_ms)).monospace()); });
                    row.col(|ui| { ui.label(&c.status); });
                    row.col(|ui| { ui.label(&c.invoke); });
                    row.col(|ui| {
                        let ext = if c.external_method { RichText::new(format!("{}.{}{}", c.module, c.method, c.spec)).italics() } else { RichText::new(format!("{}.{}{}", c.module, c.method, c.spec)) };
                        ui.label(ext).on_hover_text(format!("{}:{}{}", c.file, c.line, if c.external_method { "\nmethod defined in another image" } else { "" }));
                    });
                    if row.response().clicked() {
                        clicked = Some(c.obj);
                    }
                });
            });
        self.ci_sort = sort;
        if let Some(o) = clicked {
            self.select(o);
        }
    }

    fn ci_group_table(&mut self, ui: &mut Ui, m: &Model) {
        let g = self.ci_group;
        let mut groups: HashMap<String, (u64, u64, u64, f32)> = HashMap::new();
        for c in &m.cis {
            let e = groups.entry(ci_group_key(c, g)).or_default();
            e.0 += 1;
            e.1 += c.native_bytes + c.wrapper_bytes;
            e.2 += c.inferred_bytes;
            e.3 += c.infer_self_ms;
        }
        let rows: Vec<(String, (u64, u64, u64, f32))> = {
            let mut v: Vec<_> = groups.into_iter().collect();
            let (sc, desc) = (self.ci_groups.col, self.ci_groups.desc);
            v.sort_by(|a, b| {
                let o = match sc {
                    0 => a.0.cmp(&b.0),
                    1 => a.1.0.cmp(&b.1.0),
                    2 => a.1.1.cmp(&b.1.1),
                    3 => a.1.2.cmp(&b.1.2),
                    _ => a.1.3.total_cmp(&b.1.3),
                };
                if desc { o.reverse() } else { o }
            });
            v
        };
        ui.label(RichText::new(format!("{} groups", rows.len())).weak());
        let max = rows.iter().map(|r| r.1.1).max().unwrap_or(1).max(1);
        let color = bar_color(ui);
        let mut sort = std::mem::take(&mut self.ci_groups);
        let mut clicked = None;
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::remainder().at_least(300.0).clip(true))
            .column(Column::exact(70.0))
            .column(Column::exact(90.0))
            .column(Column::exact(90.0))
            .column(Column::exact(80.0))
            .column(Column::exact(140.0))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "group", 0, &mut sort, false));
                h.col(|ui| sort_header(ui, "CIs", 1, &mut sort, true));
                h.col(|ui| sort_header(ui, "native", 2, &mut sort, true));
                h.col(|ui| sort_header(ui, "inferred", 3, &mut sort, true));
                h.col(|ui| sort_header(ui, "infer ms", 4, &mut sort, true));
                h.col(|_| {});
            })
            .body(|body| {
                body.rows(18.0, rows.len(), |mut row| {
                    let (k, (n, nat, inf, ms)) = &rows[row.index()];
                    row.col(|ui| { ui.label(k); });
                    row.col(|ui| { ui.label(RichText::new(n.to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(human(*nat)).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(human(*inf)).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(format!("{ms:.1}")).monospace()); });
                    row.col(|ui| data_bar(ui, *nat as f32 / max as f32, color));
                    if row.response().clicked() {
                        clicked = Some(k.clone());
                    }
                });
            });
        self.ci_groups = sort;
        if let Some(k) = clicked {
            self.ci_group_sel = Some(k);
            self.ci_sort.key.clear();
        }
    }

    fn methods(&mut self, ui: &mut Ui, m: &Model) {
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.m_filter).hint_text("filter").desired_width(300.0));
            ui.label(RichText::new(format!("{} methods", m.methods.len())).weak());
        });
        let key = format!("{}{}{}", self.m_filter, self.m_sort.col, self.m_sort.desc);
        if self.m_sort.key != key {
            let f = self.m_filter.to_lowercase();
            let mut order: Vec<usize> = (0..m.methods.len())
                .filter(|&i| {
                    let r = &m.methods[i];
                    f.is_empty() || [&r.name, &r.module, &r.file, &r.sig].iter().any(|s| s.to_lowercase().contains(&f))
                })
                .collect();
            let sc = self.m_sort.col;
            order.sort_by(|&a, &b| {
                let (x, y) = (&m.methods[a], &m.methods[b]);
                match sc {
                    0 => (&x.module, &x.name).cmp(&(&y.module, &y.name)),
                    1 => x.sig.cmp(&y.sig),
                    _ => (&x.file, x.line).cmp(&(&y.file, y.line)),
                }
            });
            if self.m_sort.desc {
                order.reverse();
            }
            self.m_sort.order = order;
            self.m_sort.key = key;
        }
        let mut sort = std::mem::take(&mut self.m_sort);
        let order = sort.order.clone();
        let mut clicked = None;
        let mut goto_src = None;
        let sel = self.selected();
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::initial(260.0).clip(true).resizable(true))
            .column(Column::initial(380.0).clip(true).resizable(true))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "method", 0, &mut sort, false));
                h.col(|ui| sort_header(ui, "signature", 1, &mut sort, false));
                h.col(|ui| sort_header(ui, "location", 2, &mut sort, false));
            })
            .body(|body| {
                body.rows(18.0, order.len(), |mut row| {
                    let r = &m.methods[order[row.index()]];
                    row.set_selected(sel == Some(r.obj));
                    row.col(|ui| { ui.label(format!("{}.{}", r.module, r.name)); });
                    row.col(|ui| { ui.label(&r.sig); });
                    row.col(|ui| {
                        let short = r.file.rsplit('/').next().unwrap_or("");
                        if ui.link(format!("{short}:{}", r.line)).on_hover_text(&r.file).clicked() {
                            goto_src = Some((r.file.clone(), r.line));
                        }
                    });
                    if row.response().clicked() {
                        clicked = Some(r.obj);
                    }
                });
            });
        self.m_sort = sort;
        if let Some(o) = clicked {
            self.select(o);
        }
        if let Some((f, l)) = goto_src {
            self.goto_source(m, &f, l);
        }
    }

    fn goto_source(&mut self, m: &Model, file: &str, line: i64) {
        if let Some(i) = m.srctext.iter().position(|(p, _)| same_file(file, p)) {
            self.src_sel = i;
            self.src_scroll_line = Some(line.max(1) as usize - 1);
            self.tab = Tab::Sources;
        }
    }

    fn sources(&mut self, ui: &mut Ui, m: &Model) {
        if m.srctext.is_empty() {
            ui.label("No embedded sources.");
            return;
        }
        egui::Panel::left("srcfiles").resizable(true).default_size(260.0).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, (p, t)) in m.srctext.iter().enumerate() {
                    let short = p.rsplit('/').next().unwrap_or(p);
                    if ui.selectable_label(self.src_sel == i, short).on_hover_text(format!("{p}\n{}", human(t.len() as u64))).clicked() {
                        self.src_sel = i;
                        self.src_scroll_line = Some(0);
                    }
                }
            });
        });
        let (path, text) = &m.srctext[self.src_sel.min(m.srctext.len() - 1)];
        // Methods per line in this file
        let mut per_line: std::collections::HashMap<i64, usize> = Default::default();
        for r in &m.methods {
            if same_file(&r.file, path) {
                *per_line.entry(r.line).or_default() += 1;
            }
        }
        let lines: Vec<&str> = text.lines().collect();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
        let mut sa = egui::ScrollArea::both().auto_shrink(false);
        if let Some(l) = self.src_scroll_line.take() {
            sa = sa.vertical_scroll_offset((l.saturating_sub(5)) as f32 * (row_h + ui.spacing().item_spacing.y));
        }
        let accent = bar_color(ui);
        sa.show_rows(ui, row_h, lines.len(), |ui, range| {
            for i in range {
                ui.horizontal(|ui| {
                    let n = per_line.get(&(i as i64 + 1)).copied().unwrap_or(0);
                    let gutter = if n > 0 { RichText::new(format!("{:>5} ●", i + 1)).monospace().color(accent) } else { RichText::new(format!("{:>5}  ", i + 1)).monospace().weak() };
                    ui.label(gutter).on_hover_text(if n > 0 { format!("{n} method(s) defined here") } else { String::new() });
                    ui.label(RichText::new(lines[i]).monospace());
                });
            }
        });
    }

    fn deps(&mut self, ui: &mut Ui, m: &Model) {
        let Some(p) = &m.w.target().header.pkg else { return };
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("deps").num_columns(3).striped(true).show(ui, |ui| {
                ui.strong("module");
                ui.strong("uuid");
                ui.strong("resolved to");
                ui.end_row();
                for d in &p.required_modules {
                    ui.label(&d.name);
                    ui.label(RichText::new(&d.uuid).monospace().weak());
                    let found = m.w.images.iter().find(|im| im.header.pkg.as_ref().is_some_and(|pk| pk.worklist.iter().any(|x| x.name == d.name && x.build_id_lo == d.build_id_lo)));
                    let missing = m.w.missing.iter().any(|x| x.name == d.name && x.uuid == d.uuid);
                    match (found, missing) {
                        (Some(im), _) => ui.label(im.path.display().to_string()),
                        (None, false) => ui.label("system image"),
                        (None, true) => ui.colored_label(ui.visuals().warn_fg_color, "not found"),
                    };
                    ui.end_row();
                }
            });
        });
    }

    fn val_ui(&self, ui: &mut Ui, m: &Model, v: Val, nav: &mut Option<Obj>) {
        let text = m.w.show(v, 3);
        match v {
            Val::Obj(o) => {
                let mut label = text;
                if o.img != m.w.target {
                    label = format!("{label}   [{}]", m.w.img(o.img).display_name());
                }
                if link_trunc(ui, &label).clicked() {
                    *nav = Some(o);
                }
            }
            _ => {
                ui.add(egui::Label::new(RichText::new(text).weak()).truncate());
            }
        }
    }

    fn inspector(&mut self, ui: &mut Ui, m: &Model) {
        let Some(o) = self.selected() else { return };
        let mut nav = None;
        ui.horizontal(|ui| {
            if ui.add_enabled(self.hist_pos > 1, egui::Button::new("⏴")).on_hover_text("back (alt+←)").clicked() {
                self.hist_pos -= 1;
                self.referrers = None;
            }
            if ui.add_enabled(self.hist_pos < self.history.len(), egui::Button::new("⏵")).on_hover_text("forward (alt+→)").clicked() {
                self.hist_pos += 1;
                self.referrers = None;
            }
            ui.strong("Inspector");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("✕").clicked() {
                    self.history.clear();
                    self.hist_pos = 0;
                }
            });
        });
        let Some(o2) = self.selected() else { return };
        let o = if o2 != o { o2 } else { o };
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            let w = &m.w;
            ui.add(egui::Label::new(RichText::new(w.show(Val::Obj(o), 5)).strong()).wrap());
            let ty = w.type_info(o).map(|t| w.show(Val::Obj(t.obj), 4)).unwrap_or_else(|| "?".into());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("::").weak());
                if let Some(t) = w.type_of(o) {
                    if ui.link(&ty).clicked() {
                        nav = Some(t);
                    }
                } else {
                    ui.label(ty);
                }
            });
            let size = m.find(o).map(|i| m.entry(i).size);
            ui.label(RichText::new(format!(
                "{} @ {}{}{}",
                w.img(o.img).display_name(),
                if o.cst { "const+" } else { "" },
                o.off,
                size.map(|s| format!("  ·  {s} bytes")).unwrap_or_default()
            )).weak().monospace());
            if let Some(s) = inspect::string_value(w, o) {
                ui.add_space(4.0);
                let shown: String = s.chars().take(2000).collect();
                ui.label(RichText::new(format!("{shown:?}")).monospace());
            }
            if let Some(c) = m.cis.iter().find(|c| c.obj == o)
                && (c.root.is_some() || c.native_symbol.is_some())
            {
                ui.add_space(4.0);
                egui::Grid::new("ciextra").num_columns(2).show(ui, |ui| {
                    if let Some(s) = &c.native_symbol {
                        ui.label(RichText::new("native").weak());
                        ui.label(RichText::new(format!("{s}  ({} B + {} B wrapper)", c.native_bytes, c.wrapper_bytes)).monospace());
                        ui.end_row();
                    }
                    if let Some(p) = &c.parent {
                        ui.label(RichText::new("requested by").weak());
                        ui.add(egui::Label::new(p).truncate());
                        ui.end_row();
                    }
                    if let Some(r) = &c.root {
                        ui.label(RichText::new("inference root").weak());
                        ui.add(egui::Label::new(r).truncate());
                        ui.end_row();
                    }
                });
            }
            if let Some(c) = m.cis.iter().find(|c| c.obj == o)
                && let (Some(addr), Some(buf)) = (c.native_addr, w.target().native_bytes.as_ref())
            {
                egui::CollapsingHeader::new(format!("disassembly ({} bytes)", c.native_bytes)).id_salt(("asm", o.off)).show(ui, |ui| {
                    match pkgimg_core::native::disassemble(buf, addr, c.native_bytes) {
                        Ok(lines) => {
                            let text: String = lines.iter().map(|(a, t)| format!("{a:8x}  {t}\n")).collect();
                            ui.label(RichText::new(text).monospace().small());
                        }
                        Err(e) => {
                            ui.label(e.to_string());
                        }
                    }
                });
            }
            let fields = inspect::fields(w, o);
            if !fields.is_empty() {
                ui.add_space(6.0);
                egui::Grid::new("fields").num_columns(2).striped(true).show(ui, |ui| {
                    for f in fields {
                        ui.label(RichText::new(&f.name).monospace()).on_hover_text(format!("{} @ +{}", f.ty, f.offset));
                        match f.value {
                            FieldValue::Ptr(v) => self.val_ui(ui, m, v, &mut nav),
                            FieldValue::Bits(b) => { ui.label(RichText::new(b).monospace()); }
                        }
                        ui.end_row();
                    }
                });
            }
            if let Some((n, elems)) = inspect::elements(w, o, 500) {
                ui.add_space(6.0);
                ui.collapsing(format!("elements ({n})"), |ui| {
                    egui::Grid::new("elems").num_columns(2).show(ui, |ui| {
                        for (i, e) in elems.into_iter().enumerate() {
                            ui.label(RichText::new(format!("[{}]", i + 1)).monospace().weak());
                            self.val_ui(ui, m, e, &mut nav);
                            ui.end_row();
                        }
                        if n > 500 {
                            ui.label("…");
                            ui.end_row();
                        }
                    });
                });
            }
            ui.add_space(6.0);
            if o.img == w.target {
                match &self.referrers {
                    Some((ro, refs)) if *ro == o => {
                        ui.collapsing(format!("referenced from ({}{})", refs.len(), if refs.len() >= 1000 { "+" } else { "" }), |ui| {
                            for (i, label) in refs {
                                let e = &m.objs[*i];
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(label).monospace().weak());
                                    if link_trunc(ui, &w.show(Val::Obj(e.obj), 3)).clicked() {
                                        nav = Some(e.obj);
                                    }
                                });
                            }
                        });
                    }
                    _ => {
                        if ui.button("Find referrers").clicked() {
                            self.referrers = Some((o, inspect::referrers(w, w.target, &m.objs, o)));
                        }
                    }
                }
            }
            ui.add_space(6.0);
            ui.checkbox(&mut self.show_hex, "hex");
            if self.show_hex {
                let len = size.unwrap_or(64).min(1024);
                ui.label(RichText::new(inspect::hexdump(w, o, len)).monospace().small());
            }
        });
        if let Some(n) = nav {
            self.select(n);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn shellexpand(s: &str) -> std::path::PathBuf {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(h) = std::env::var_os("HOME")
    {
        return std::path::Path::new(&h).join(rest);
    }
    std::path::PathBuf::from(s)
}

/// Whether a method's `file` refers to an embedded source path (`@depot/...` or absolute).
fn same_file(method_file: &str, src: &str) -> bool {
    let s = src.strip_prefix("@depot").unwrap_or(src);
    method_file == src || method_file.ends_with(s) || s.ends_with(method_file)
}

/// A single-line, truncated hyperlink (full text on hover).
fn link_trunc(ui: &mut Ui, text: &str) -> egui::Response {
    let color = ui.visuals().hyperlink_color;
    let r = ui.add(egui::Label::new(RichText::new(text).color(color)).truncate().sense(Sense::click()));
    if r.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    r
}

#[cfg(target_arch = "wasm32")]
mod web {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    /// URLs from `?load=a,b,c`.
    pub fn load_param() -> Option<Vec<String>> {
        let search = web_sys::window()?.location().search().ok()?;
        let q = search.strip_prefix('?')?;
        let v = q.split('&').find_map(|kv| kv.strip_prefix("load="))?;
        let v = js_sys::decode_uri_component(v).ok().map(String::from).unwrap_or_else(|| v.to_string());
        let urls: Vec<String> = v.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        (!urls.is_empty()).then_some(urls)
    }

    pub async fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
        let window = web_sys::window().ok_or("no window")?;
        let resp = JsFuture::from(window.fetch_with_str(url)).await.map_err(|e| format!("{e:?}"))?;
        let resp: web_sys::Response = resp.dyn_into().map_err(|_| "not a Response")?;
        if !resp.ok() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let buf = JsFuture::from(resp.array_buffer().map_err(|e| format!("{e:?}"))?).await.map_err(|e| format!("{e:?}"))?;
        Ok(js_sys::Uint8Array::new(&buf).to_vec())
    }
}
