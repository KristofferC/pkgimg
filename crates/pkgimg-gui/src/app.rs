use crate::model::Model;
use egui::{Color32, RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use pkgimg_core::analysis::{Group, SectionSel};
use pkgimg_core::insights::{Link, Severity};
use pkgimg_core::inspect::{self, FieldValue};
use pkgimg_core::{Obj, Val};
use std::collections::HashMap;
use std::sync::mpsc;

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    Insights,
    Heap,
    Objects,
    Compiled,
    Methods,
    Sources,
    Deps,
}

const TABS: [(Tab, &str); 8] = [
    (Tab::Overview, "Overview"),
    (Tab::Insights, "Insights"),
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

#[derive(Clone, Copy, PartialEq, Debug)]
enum MGroup {
    None,
    Function,
    Location,
}

fn m_group_key(r: &pkgimg_core::analysis::MethodRow, g: MGroup) -> String {
    match g {
        MGroup::None => String::new(),
        MGroup::Function => r.func.clone(),
        MGroup::Location => format!("{}:{}", r.file, r.line),
    }
}

/// A place in a document's navigation history: the view and the inspected object.
#[derive(Clone, PartialEq)]
struct Loc {
    tab: Tab,
    sel: Option<Obj>,
    obj_exact: Option<u32>,
    ci_group: CiGroup,
    ci_group_sel: Option<String>,
    m_group: MGroup,
    m_group_sel: Option<String>,
    src_sel: usize,
}

#[derive(Default)]
struct Sorted {
    col: usize,
    desc: bool,
    order: Vec<usize>,
    /// Inputs the order was computed for; recompute when they change.
    key: String,
}

/// One open image (a document tab): its model and all view state.
struct Doc {
    state: State,
    /// Display name for the document tab.
    title: String,
    /// Canonical path of the target image, to switch to this tab when it is opened again.
    source: Option<std::path::PathBuf>,
    /// Image to open in another tab (dependency links).
    open_request: Option<Load>,
    /// Replacement for this tab's image (reload with another system image).
    reload: Option<Load>,
    tab: Tab,
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
    ci_group_rows: Vec<(String, (u64, u64, u64, f32))>,
    ci_sort: Sorted,
    // methods
    m_filter: String,
    m_group: MGroup,
    m_group_sel: Option<String>,
    m_groups: Sorted,
    m_group_rows: Vec<(String, (u64, u64, u64, bool))>,
    m_sort: Sorted,
    // sources
    src_sel: usize,
    src_scroll_line: Option<usize>,
    /// Insight (by kind) to scroll to on the insights tab.
    insight_scroll: Option<&'static str>,
    // inspector
    sel: Option<Obj>,
    /// Visited locations; `history[hist_pos]` is the current one.
    history: Vec<Loc>,
    hist_pos: usize,
    referrers: Option<(Obj, Vec<(usize, String)>)>,
    show_hex: bool,
}

pub struct App {
    docs: Vec<Doc>,
    active: usize,
    path_input: String,
    #[cfg(not(target_arch = "wasm32"))]
    browser: crate::browser::Browser,
    show_browser: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, initial: Option<Load>) -> App {
        cc.egui_ctx.options_mut(|o| o.zoom_with_keyboard = true);
        let mut app = App {
            docs: vec![],
            active: 0,
            path_input: String::new(),
            #[cfg(not(target_arch = "wasm32"))]
            browser: crate::browser::Browser::new(),
            show_browser: false,
        };
        if let Some(l) = initial {
            app.open(&cc.egui_ctx, l);
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
        self.push(Doc::new(State::Loading(rx, label.clone()), label, None));
    }

    /// Open `load` in a new tab, or switch to the tab that already shows that file.
    fn open(&mut self, ctx: &egui::Context, load: Load) {
        self.show_browser = false;
        let source = Doc::source_of(&load);
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(p) = &source {
            self.browser.remember(p);
        }
        let same_sysimage = matches!(&load, Load::Paths(_, None));
        if let Some(i) = self.docs.iter().position(|d| source.is_some() && d.source == source)
            && same_sysimage
        {
            self.active = i;
            if matches!(self.docs[i].state, State::Failed(_)) {
                self.docs[i] = Doc::start(ctx, load);
            }
            return;
        }
        self.push(Doc::start(ctx, load));
    }

    fn push(&mut self, d: Doc) {
        self.docs.push(d);
        self.active = self.docs.len() - 1;
    }

    fn close(&mut self, i: usize) {
        if i >= self.docs.len() {
            return;
        }
        self.docs.remove(i);
        if self.active > i || self.active >= self.docs.len() {
            self.active = self.active.saturating_sub(1);
        }
    }

    fn doc(&self) -> Option<&Doc> {
        self.docs.get(self.active)
    }

    #[cfg(test)]
    pub fn browser_mut(&mut self) -> &mut crate::browser::Browser {
        &mut self.browser
    }

    #[cfg(test)]
    pub fn is_ready(&self) -> bool {
        self.doc().is_some_and(|d| matches!(d.state, State::Ready(_)))
    }

    /// Select the code instance with the most native code (screenshot tests).
    #[cfg(test)]
    pub fn select_largest_ci(&mut self) {
        let Some(d) = self.docs.get_mut(self.active) else { return };
        let State::Ready(m) = &d.state else { return };
        if let Some(c) = m.cis.iter().max_by_key(|c| c.native_bytes) {
            let o = c.obj;
            d.select(o);
        }
    }

    /// Open the dependency named `name` of the active image (screenshot tests).
    #[cfg(test)]
    pub fn open_dependency(&mut self, ctx: &egui::Context, name: &str) -> bool {
        let Some(State::Ready(m)) = self.doc().map(|d| &d.state) else { return false };
        let Some(im) = m.w.images.iter().find(|im| im.header.pkg.as_ref().is_some_and(|p| p.worklist.iter().any(|x| x.name == name))) else { return false };
        let l = image_load(m, im);
        self.open(ctx, l);
        true
    }

    /// Document tabs: one per open image, plus a button for the file browser.
    fn doc_tabs(&mut self, ui: &mut Ui) {
        let mut close = None;
        for (i, d) in self.docs.iter().enumerate() {
            let selected = i == self.active && !self.show_browser;
            let text = match &d.state {
                State::Loading(..) => RichText::new(format!("{} …", d.title)).weak(),
                State::Failed(_) => RichText::new(format!("⚠ {}", d.title)).color(ui.visuals().warn_fg_color),
                State::Ready(_) => RichText::new(&d.title),
            };
            let hover = d.source.as_ref().map_or_else(|| d.title.clone(), |p| p.display().to_string());
            let r = ui.selectable_label(selected, text).on_hover_text(format!("{hover}\nmiddle-click or ctrl+w to close"));
            if r.clicked() {
                self.active = i;
                self.show_browser = false;
            }
            if r.middle_clicked() {
                close = Some(i);
            }
            if ui.add(egui::Button::new("×").frame(false)).on_hover_text("close").clicked() {
                close = Some(i);
            }
            ui.add_space(4.0);
        }
        #[cfg(not(target_arch = "wasm32"))]
        if !self.docs.is_empty()
            && ui.selectable_label(self.show_browser, "➕ Open…").on_hover_text("browse cache files (ctrl+o)").clicked()
        {
            self.show_browser = !self.show_browser;
        }
        if let Some(i) = close {
            self.close(i);
        }
    }

    fn welcome(&mut self, ui: &mut Ui) {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
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
                    self.open(&ctx, Load::Paths(vec![p], None));
                }
            });
        });
    }
}

impl Doc {
    fn new(state: State, title: String, source: Option<std::path::PathBuf>) -> Doc {
        Doc {
            state,
            title,
            source,
            open_request: None,
            reload: None,
            tab: Tab::Overview,
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
            ci_group_rows: vec![],
            ci_sort: Sorted { col: 0, desc: true, ..Default::default() },
            m_filter: String::new(),
            m_group: MGroup::None,
            m_group_sel: None,
            m_groups: Sorted { col: 1, desc: true, ..Default::default() },
            m_group_rows: vec![],
            m_sort: Sorted::default(),
            src_sel: 0,
            src_scroll_line: None,
            insight_scroll: None,
            sel: None,
            history: vec![],
            hist_pos: 0,
            referrers: None,
            show_hex: false,
        }
    }

    fn source_of(load: &Load) -> Option<std::path::PathBuf> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Load::Paths(p, _) = load
            && let Some(first) = p.first()
        {
            return Some(std::fs::canonicalize(first).unwrap_or_else(|_| first.clone()));
        }
        let _ = load;
        None
    }

    /// Start loading `load` off the UI thread (on native).
    fn start(ctx: &egui::Context, load: Load) -> Doc {
        let source = Doc::source_of(&load);
        let (tx, rx) = mpsc::channel();
        let label = match &load {
            Load::Paths(p, _) => p.first().map(|p| p.display().to_string()).unwrap_or_default(),
            Load::Bytes(b) => b.first().map(|b| b.0.clone()).unwrap_or_default(),
        };
        let title = label.rsplit('/').next().unwrap_or(&label).to_string();
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
        Doc::new(State::Loading(rx, label), title, source)
    }

    /// Pick up a finished load.
    fn poll(&mut self) {
        let State::Loading(rx, _) = &self.state else { return };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err("The image loader stopped unexpectedly. Try opening another image.".into()),
        };
        self.state = match result {
            Ok(m) => {
                self.title = m.w.target().display_name();
                State::Ready(Box::new(m))
            }
            Err(e) => State::Failed(e),
        };
    }

    fn select(&mut self, o: Obj) {
        self.sel = Some(o);
    }

    fn selected(&self) -> Option<Obj> {
        self.sel
    }

    fn loc(&self) -> Loc {
        Loc {
            tab: self.tab,
            sel: self.sel,
            obj_exact: self.obj_exact,
            ci_group: self.ci_group,
            ci_group_sel: self.ci_group_sel.clone(),
            m_group: self.m_group,
            m_group_sel: self.m_group_sel.clone(),
            src_sel: self.src_sel,
        }
    }

    /// Add the current location to the history if it changed this frame.
    fn record(&mut self) {
        let cur = self.loc();
        if self.history.get(self.hist_pos) == Some(&cur) {
            return;
        }
        if !self.history.is_empty() {
            self.history.truncate(self.hist_pos + 1);
        }
        self.history.push(cur);
        self.hist_pos = self.history.len() - 1;
    }

    fn can_go(&self, back: bool) -> bool {
        if back { self.hist_pos > 0 } else { self.hist_pos + 1 < self.history.len() }
    }

    /// Step back or forward in the history.
    fn go(&mut self, back: bool) {
        if !self.can_go(back) {
            return;
        }
        if back { self.hist_pos -= 1 } else { self.hist_pos += 1 }
        let l = self.history[self.hist_pos].clone();
        self.tab = l.tab;
        self.sel = l.sel;
        self.obj_exact = l.obj_exact;
        self.ci_group = l.ci_group;
        self.ci_group_sel = l.ci_group_sel;
        self.m_group = l.m_group;
        self.m_group_sel = l.m_group_sel;
        self.src_sel = l.src_sel;
        for k in [&mut self.obj_rows.key, &mut self.ci_groups.key, &mut self.ci_sort.key, &mut self.m_groups.key, &mut self.m_sort.key] {
            k.clear();
        }
    }

    fn back_forward(&mut self, ctx: &egui::Context) {
        let (back, fwd) = ctx.input(|i| {
            (
                i.pointer.button_pressed(egui::PointerButton::Extra1) || (i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft)),
                i.pointer.button_pressed(egui::PointerButton::Extra2) || (i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight)),
            )
        });
        if back {
            self.go(true);
        }
        if fwd {
            self.go(false);
        }
    }

    /// Image summary line, resolution warnings and view tabs (top panel).
    fn header(&mut self, ui: &mut Ui) {
        let State::Ready(m) = &self.state else { return };
        ui.horizontal(|ui| {
            let im = m.w.target();
            ui.label(RichText::new(im.display_name()).strong());
            ui.add(egui::Label::new(RichText::new(format!("Julia {}  ·  loaded in {:.0?}", im.header.base.julia_version, m.load_time)).weak()))
                .on_hover_text(im.path.display().to_string());
            if ui.small_button("Copy path").on_hover_text(im.path.display().to_string()).clicked() {
                ui.ctx().copy_text(im.path.display().to_string());
            }
        });
        if m.w.sysimg.is_none() || !m.w.missing.is_empty() {
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
                        self.reload = Some(Load::Paths(vec![m.w.target().path.clone()], Some(shellexpand(&self.sysimage_input))));
                    }
                }
                #[cfg(target_arch = "wasm32")]
                ui.label("Drop the matching sys.so together with the .ji/.so.");
            });
        }
        let flagged = m.insights.iter().filter(|i| i.severity > Severity::Info).count();
        let mut go = None;
        ui.horizontal(|ui| {
            if ui.add_enabled(self.can_go(true), egui::Button::new("⏴")).on_hover_text("back (alt+←)").clicked() {
                go = Some(true);
            }
            if ui.add_enabled(self.can_go(false), egui::Button::new("⏵")).on_hover_text("forward (alt+→)").clicked() {
                go = Some(false);
            }
            ui.separator();
            for (t, name) in TABS {
                let text = if t == Tab::Insights && flagged > 0 { format!("{name} ({flagged})") } else { name.to_string() };
                if ui.selectable_label(self.tab == t, text).clicked() {
                    self.tab = t;
                }
            }
        });
        if let Some(back) = go {
            self.go(back);
        }
    }

    fn ui(&mut self, ui: &mut Ui) {
        let state = std::mem::replace(&mut self.state, State::Failed(String::new()));
        match &state {
            State::Ready(_) => {}
            State::Loading(_, label) => {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.heading("Reading image");
                        ui.label(label);
                        ui.label(RichText::new("Resolving dependencies and computing heap and code statistics…").weak());
                    });
                });
            }
            State::Failed(e) => {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.heading("Could not open image");
                    ui.colored_label(ui.visuals().error_fg_color, e);
                    if ui.button("Copy error").clicked() {
                        ui.ctx().copy_text(e.clone());
                    }
                });
            }
        }
        let State::Ready(mut m) = state else {
            self.state = state;
            return;
        };
        if self.selected().is_some() {
            egui::Panel::right("inspector").resizable(true).default_size(480.0).max_size(900.0).show(ui, |ui| {
                self.inspector(ui, &m);
            });
        }
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Overview => self.overview(ui, &mut m),
            Tab::Insights => self.insights(ui, &m),
            Tab::Heap => self.heap(ui, &mut m),
            Tab::Objects => self.objects(ui, &m),
            Tab::Compiled => self.compiled(ui, &m),
            Tab::Methods => self.methods(ui, &m),
            Tab::Sources => self.sources(ui, &m),
            Tab::Deps => self.deps(ui, &m),
        });
        self.state = State::Ready(m);
        self.record();
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

fn severity_color(ui: &Ui, s: Severity) -> Color32 {
    match s {
        Severity::High => ui.visuals().error_fg_color,
        Severity::Notable => ui.visuals().warn_fg_color,
        Severity::Info => bar_color(ui),
    }
}

/// A small colored severity tag.
fn severity_badge(ui: &mut Ui, s: Severity) {
    let text = match s {
        Severity::High => "HIGH",
        Severity::Notable => "NOTABLE",
        Severity::Info => "INFO",
    };
    let color = severity_color(ui, s);
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(3.0)
        .inner_margin(egui::Margin::symmetric(4, 0))
        .show(ui, |ui| ui.label(RichText::new(text).small().strong().color(color)));
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

/// Table labels must let the row receive clicks instead of starting text selection.
/// This changes only the table's UI; source and inspector panels remain selectable.
pub(crate) fn clickable_table(ui: &mut Ui) -> TableBuilder<'_> {
    ui.style_mut().interaction.selectable_labels = false;
    TableBuilder::new(ui).striped(true).sense(Sense::click())
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

/// Open another image of the model's world with the same system image.
fn image_load(m: &Model, im: &pkgimg_core::Image) -> Load {
    let sys = m.w.sysimg.map(|s| m.w.img(s).path.clone());
    Load::Paths(vec![im.path.clone()], sys)
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Dropped files open in a new tab.
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let paths: Vec<_> = dropped.iter().map(|f| f.path().to_path_buf()).collect();
                self.open(&ctx, Load::Paths(paths, None));
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
                self.push(Doc::new(State::Loading(rx, label.clone()), label, None));
            }
        }
        for d in &mut self.docs {
            d.poll();
        }
        let (toggle_browser, close, next, prev) = ctx.input(|i| {
            let ctrl_tab = i.modifiers.command && i.key_pressed(egui::Key::Tab);
            (
                i.modifiers.command && i.key_pressed(egui::Key::O),
                i.modifiers.command && i.key_pressed(egui::Key::W),
                (ctrl_tab && !i.modifiers.shift) || (i.modifiers.command && i.key_pressed(egui::Key::PageDown)),
                (ctrl_tab && i.modifiers.shift) || (i.modifiers.command && i.key_pressed(egui::Key::PageUp)),
            )
        });
        if toggle_browser {
            self.show_browser = !self.show_browser;
        }
        if close {
            self.close(self.active);
        }
        let n = self.docs.len().max(1);
        if next {
            self.active = (self.active + 1) % n;
        }
        if prev {
            self.active = (self.active + n - 1) % n;
        }
        if let Some(d) = self.docs.get_mut(self.active) {
            d.back_forward(&ctx);
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("pkgimg");
                ui.separator();
                self.doc_tabs(ui);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::widgets::global_theme_preference_switch(ui);
                });
            });
            if !self.show_browser
                && let Some(d) = self.docs.get_mut(self.active)
            {
                ui.separator();
                d.header(ui);
            }
        });

        let failed = self.doc().is_some_and(|d| matches!(d.state, State::Failed(_)));
        #[cfg(not(target_arch = "wasm32"))]
        if self.show_browser || self.docs.is_empty() || failed {
            let mut pick = None;
            egui::CentralPanel::default().show(ui, |ui| {
                if let Some(Doc { state: State::Failed(e), .. }) = self.docs.get(self.active).filter(|_| !self.show_browser) {
                    ui.heading("Could not open image");
                    ui.colored_label(ui.visuals().error_fg_color, e);
                    if ui.button("Copy error").clicked() { ui.ctx().copy_text(e.clone()); }
                    ui.label("Choose another cache below. Supported images: Julia 1.13 and master, 64-bit.");
                    ui.separator();
                }
                pick = self.browser.ui(ui);
            });
            if let Some(p) = pick {
                // A failed tab is replaced; otherwise the pick opens in a new tab.
                if failed && !self.show_browser {
                    self.close(self.active);
                }
                self.open(&ctx, Load::Paths(vec![p.ji], p.sysimage));
            }
            return;
        }
        let _ = failed;
        let Some(d) = self.docs.get_mut(self.active) else {
            egui::CentralPanel::default().show(ui, |ui| self.welcome(ui));
            return;
        };
        d.ui(ui);
        if let Some(l) = d.reload.take() {
            self.docs[self.active] = Doc::start(&ctx, l);
        } else if let Some(l) = d.open_request.take() {
            self.open(&ctx, l);
        }
    }
}

impl Doc {
    fn overview(&mut self, ui: &mut Ui, m: &mut Model) {
        let rows: Vec<_> = m.hist(Group::Type, SectionSel::All).iter().take(20).cloned().collect();
        let m: &Model = m;
        let im = m.w.target();
        let st = &m.stats;
        egui::ScrollArea::vertical().show(ui, |ui| {
            let flagged: Vec<_> = m.insights.iter().filter(|i| i.severity > Severity::Info).collect();
            if let Some(first) = flagged.first() {
                let color = severity_color(ui, first.severity);
                egui::Frame::group(ui.style()).stroke(egui::Stroke::new(1.5, color)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.heading("Worth a look");
                        if ui.link("All insights").clicked() {
                            self.tab = Tab::Insights;
                        }
                    });
                    for ins in &flagged {
                        ui.horizontal(|ui| {
                            severity_badge(ui, ins.severity);
                            if ui.link(RichText::new(&ins.title).strong()).clicked() {
                                self.tab = Tab::Insights;
                                self.insight_scroll = Some(ins.kind);
                            }
                            ui.add(egui::Label::new(RichText::new(&ins.summary).weak()).truncate());
                        });
                    }
                });
                ui.add_space(12.0);
            }
            ui.heading("At a glance");
            ui.label(RichText::new("Explore what occupies this image and where compiled code comes from.").weak());
            ui.add_space(8.0);
            ui.columns(3, |cols| {
                for (i, (title, value, hint, tab)) in [
                    ("Serialized heap", human(im.heap.data.len() as u64), "Uncompressed serialized heap", Tab::Heap),
                    ("Native code", human(st.native_bytes), "Attributed to code instances, including wrappers", Tab::Compiled),
                    ("Method definitions", st.n_methods.to_string(), "Method definitions in this image", Tab::Methods),
                ].into_iter().enumerate() {
                    let ui = &mut cols[i];
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.label(RichText::new(title).weak());
                        ui.label(RichText::new(value).size(25.0).strong().color(bar_color(ui)));
                        ui.label(RichText::new(hint).small().weak());
                        if ui.link(format!("Explore {title}")).clicked() { self.tab = tab; }
                    });
                }
            });
            ui.add_space(12.0);
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
                    row("heap on disk", human(im.heap_stored_size as u64));
                    row("embedded sources", m.srctext.len().to_string());
                    row("provenance", m.provenance_path.clone().unwrap_or_else(|| "Not available — root/caller attribution needs a sidecar".into()));
                    if let Some(n) = &im.native {
                        row("native size", format!("{}  (.text {})", human(n.file_size), human(n.text_size)));
                        row("native functions", n.fvars.len().to_string());
                    }
                    row("objects", format!("{} + {} const", m.objs.len(), m.cst.iter().filter(|e| e.label != pkgimg_core::analysis::ConstLabel::MemData).count()));
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
            ui.label(RichText::new("Click a type to inspect its objects. Sizes include alignment padding.").weak());
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

    fn insights(&mut self, ui: &mut Ui, m: &Model) {
        if m.insights.is_empty() {
            ui.label("Nothing unusual found: no function has very many methods, no method very many specializations, and nothing was invalidated.");
            return;
        }
        let mut follow = None;
        let scroll = self.insight_scroll.take();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.label(RichText::new("Heuristics that flag unusual, likely costly parts of this image. Click an entry to explore it.").weak());
            ui.add_space(6.0);
            let color = bar_color(ui);
            for ins in &m.insights {
                let r = egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        severity_badge(ui, ins.severity);
                        ui.label(RichText::new(&ins.title).strong().size(16.0));
                    });
                    ui.label(&ins.summary);
                    ui.add(egui::Label::new(RichText::new(ins.detail).weak()).wrap());
                    ui.add_space(4.0);
                    let label_w = (ui.available_width() * 0.6).max(200.0);
                    egui::Grid::new(("insight", ins.kind)).num_columns(3).striped(true).show(ui, |ui| {
                        for it in &ins.items {
                            ui.allocate_ui(egui::vec2(label_w, 18.0), |ui| {
                                ui.set_max_width(label_w);
                                if link_trunc(ui, &it.label).on_hover_text(&it.label).clicked() {
                                    follow = Some(it.link.clone());
                                }
                            });
                            ui.label(RichText::new(&it.value).monospace());
                            ui.allocate_ui(egui::vec2(160.0, 12.0), |ui| data_bar(ui, it.weight, color));
                            ui.end_row();
                        }
                    });
                    if ins.total_items > ins.items.len() {
                        ui.label(RichText::new(format!("… {} more", ins.total_items - ins.items.len())).weak());
                    }
                });
                if scroll == Some(ins.kind) {
                    ui.scroll_to_rect(r.response.rect, Some(egui::Align::TOP));
                }
                ui.add_space(8.0);
            }
        });
        if let Some(l) = follow {
            self.follow(m, &l);
        }
    }

    /// Navigate to what an insight item refers to.
    fn follow(&mut self, m: &Model, link: &Link) {
        match link {
            Link::Function { func } => self.show_methods(MGroup::Function, func.clone()),
            Link::Location { file, line } => self.show_methods(MGroup::Location, format!("{file}:{line}")),
            Link::Specializations { method, .. } => {
                if let Some(c) = m.cis.iter().find(|c| c.def == Some(*method)) {
                    self.ci_group = CiGroup::Method;
                    self.ci_group_sel = Some(ci_group_key(c, CiGroup::Method));
                    self.ci_filter.clear();
                    self.ci_groups.key.clear();
                    self.ci_sort.key.clear();
                    self.tab = Tab::Compiled;
                }
            }
            Link::Object { obj, .. } => self.select(*obj),
        }
    }

    fn show_methods(&mut self, g: MGroup, key: String) {
        self.m_group = g;
        self.m_group_sel = Some(key);
        self.m_filter.clear();
        self.m_groups.key.clear();
        self.m_sort.key.clear();
        self.tab = Tab::Methods;
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
        let matched: u64 = self.heap_sort.order.iter().map(|&i| rows[i].bytes).sum();
        ui.label(RichText::new(format!("{} of {} groups · {} shown / {} total", self.heap_sort.order.len(), rows.len(), human(matched), human(rows.iter().map(|r| r.bytes).sum()))).weak());
        if self.heap_sort.order.is_empty() {
            ui.label("No matching types. Clear the filter or choose another section.");
            if ui.button("Clear filter").clicked() { self.heap_filter.clear(); }
        }
        let color = bar_color(ui);
        let mut clicked = None;
        let mut sort = std::mem::take(&mut self.heap_sort);
        let order = sort.order.clone();
        clickable_table(ui)
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
                    if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
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
                if ui.small_button("×").clicked() {
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
        clickable_table(ui)
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
                    if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
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
                if ui.small_button("×").clicked() {
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
        clickable_table(ui)
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
                    if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
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
        // Grouping is recomputed only when the grouping or sort changes; ties are broken by
        // key so the order is stable.
        let key = format!("{:?}|{}|{}", g, self.ci_groups.col, self.ci_groups.desc);
        if self.ci_groups.key != key {
            let mut groups: HashMap<String, (u64, u64, u64, f32)> = HashMap::new();
            for c in &m.cis {
                let e = groups.entry(ci_group_key(c, g)).or_default();
                e.0 += 1;
                e.1 += c.native_bytes + c.wrapper_bytes;
                e.2 += c.inferred_bytes;
                e.3 += c.infer_self_ms;
            }
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
                (if desc { o.reverse() } else { o }).then_with(|| a.0.cmp(&b.0))
            });
            self.ci_group_rows = v;
            self.ci_groups.key = key;
        }
        let rows = &self.ci_group_rows;
        ui.label(RichText::new(format!("{} groups", rows.len())).weak());
        let max = rows.iter().map(|r| r.1.1).max().unwrap_or(1).max(1);
        let color = bar_color(ui);
        let mut sort = std::mem::take(&mut self.ci_groups);
        let mut clicked = None;
        clickable_table(ui)
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
                    if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
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
            ui.label("Group by");
            for (g, name) in [(MGroup::None, "none"), (MGroup::Function, "function"), (MGroup::Location, "source line")] {
                if ui.selectable_label(self.m_group == g, name).clicked() {
                    self.m_group = g;
                    self.m_group_sel = None;
                    self.m_groups.key.clear();
                    self.m_sort.key.clear();
                }
            }
        });
        if self.m_group != MGroup::None && self.m_group_sel.is_none() {
            self.m_group_table(ui, m);
            return;
        }
        if let Some(sel) = self.m_group_sel.clone() {
            ui.horizontal(|ui| {
                ui.label(if self.m_group == MGroup::Function { "function =" } else { "defined at" });
                ui.strong(&sel);
                if ui.small_button("×").clicked() {
                    self.m_group_sel = None;
                    self.m_sort.key.clear();
                }
            });
        }
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.m_filter).hint_text("filter").desired_width(300.0));
            ui.label(RichText::new(format!("{} of {} methods", self.m_sort.order.len(), m.methods.len())).weak());
        });
        let key = format!("{}{}{}{:?}", self.m_filter, self.m_sort.col, self.m_sort.desc, self.m_group_sel);
        if self.m_sort.key != key {
            let f = self.m_filter.to_lowercase();
            let (g, gsel) = (self.m_group, self.m_group_sel.clone());
            let mut order: Vec<usize> = (0..m.methods.len())
                .filter(|&i| {
                    let r = &m.methods[i];
                    gsel.as_ref().is_none_or(|s| m_group_key(r, g) == *s)
                        && (f.is_empty() || [&r.func, &r.name, &r.module, &r.file, &r.sig].iter().any(|s| s.to_lowercase().contains(&f)))
                })
                .collect();
            let sc = self.m_sort.col;
            order.sort_by(|&a, &b| {
                let (x, y) = (&m.methods[a], &m.methods[b]);
                match sc {
                    0 => (&x.func, &x.module).cmp(&(&y.func, &y.module)),
                    1 => x.sig.cmp(&y.sig),
                    2 => m.method_cis[a].0.cmp(&m.method_cis[b].0),
                    3 => m.method_cis[a].1.cmp(&m.method_cis[b].1),
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
        let warn = ui.visuals().warn_fg_color;
        clickable_table(ui)
            .column(Column::initial(260.0).clip(true).resizable(true))
            .column(Column::initial(380.0).clip(true).resizable(true))
            .column(Column::exact(50.0))
            .column(Column::exact(70.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "function", 0, &mut sort, false));
                h.col(|ui| sort_header(ui, "signature", 1, &mut sort, false));
                h.col(|ui| sort_header(ui, "CIs", 2, &mut sort, true));
                h.col(|ui| sort_header(ui, "native", 3, &mut sort, true));
                h.col(|ui| sort_header(ui, "location", 4, &mut sort, false));
            })
            .body(|body| {
                body.rows(18.0, order.len(), |mut row| {
                    let i = order[row.index()];
                    let r = &m.methods[i];
                    row.set_selected(sel == Some(r.obj));
                    row.col(|ui| {
                        if r.pirate {
                            ui.label(RichText::new("⚠").color(warn)).on_hover_text("possible type piracy: no argument type is from this package");
                        }
                        let name = if r.kwcall { format!("{} (kw)", r.func) } else { r.func.clone() };
                        let text = if r.func_external { RichText::new(name).italics() } else { RichText::new(name) };
                        ui.label(text).on_hover_text(format!(
                            "method {} defined in module {}{}{}", r.name, r.module,
                            if r.kwcall { "\nkeyword-argument method (Core.kwcall)" } else { "" },
                            if r.func_external { "\nfunction owned by another module" } else { "" },
                        ));
                    });
                    row.col(|ui| { ui.label(&r.sig); });
                    let (n, nat) = m.method_cis[i];
                    row.col(|ui| { ui.label(RichText::new(n.to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(human(nat)).monospace()); });
                    row.col(|ui| {
                        let short = r.file.rsplit('/').next().unwrap_or("");
                        if ui.link(format!("{short}:{}", r.line)).on_hover_text(&r.file).clicked() {
                            goto_src = Some((r.file.clone(), r.line));
                        }
                    });
                    if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
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

    fn m_group_table(&mut self, ui: &mut Ui, m: &Model) {
        let g = self.m_group;
        let key = format!("{:?}|{}|{}", g, self.m_groups.col, self.m_groups.desc);
        if self.m_groups.key != key {
            let mut groups: HashMap<String, (u64, u64, u64, bool)> = HashMap::new();
            for (r, (n, nat)) in m.methods.iter().zip(&m.method_cis) {
                let e = groups.entry(m_group_key(r, g)).or_default();
                e.0 += 1;
                e.1 += *n as u64;
                e.2 += nat;
                e.3 |= r.func_external;
            }
            let mut v: Vec<_> = groups.into_iter().collect();
            let (sc, desc) = (self.m_groups.col, self.m_groups.desc);
            v.sort_by(|a, b| {
                let o = match sc {
                    0 => a.0.cmp(&b.0),
                    1 => a.1.0.cmp(&b.1.0),
                    2 => a.1.1.cmp(&b.1.1),
                    _ => a.1.2.cmp(&b.1.2),
                };
                (if desc { o.reverse() } else { o }).then_with(|| a.0.cmp(&b.0))
            });
            self.m_group_rows = v;
            self.m_groups.key = key;
        }
        let rows = &self.m_group_rows;
        ui.label(RichText::new(format!("{} groups · italic: function owned by another module", rows.len())).weak());
        let max = rows.iter().map(|r| r.1.0).max().unwrap_or(1).max(1);
        let color = bar_color(ui);
        let mut sort = std::mem::take(&mut self.m_groups);
        let mut clicked = None;
        clickable_table(ui)
            .column(Column::remainder().at_least(300.0).clip(true))
            .column(Column::exact(70.0))
            .column(Column::exact(70.0))
            .column(Column::exact(90.0))
            .column(Column::exact(140.0))
            .header(20.0, |mut h| {
                h.col(|ui| sort_header(ui, "group", 0, &mut sort, false));
                h.col(|ui| sort_header(ui, "methods", 1, &mut sort, true));
                h.col(|ui| sort_header(ui, "CIs", 2, &mut sort, true));
                h.col(|ui| sort_header(ui, "native", 3, &mut sort, true));
                h.col(|_| {});
            })
            .body(|body| {
                body.rows(18.0, rows.len(), |mut row| {
                    let (k, (n, cis, nat, ext)) = &rows[row.index()];
                    row.col(|ui| { ui.label(if *ext { RichText::new(k).italics() } else { RichText::new(k) }); });
                    row.col(|ui| { ui.label(RichText::new(n.to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(cis.to_string()).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(human(*nat)).monospace()); });
                    row.col(|ui| data_bar(ui, *n as f32 / max as f32, color));
                    if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        clicked = Some(k.clone());
                    }
                });
            });
        self.m_groups = sort;
        if let Some(k) = clicked {
            self.m_group_sel = Some(k);
            self.m_sort.key.clear();
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
        let mut open = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            if cfg!(not(target_arch = "wasm32")) {
                ui.label(RichText::new("Click a package to open its image in a new tab.").weak());
            }
            egui::Grid::new("deps").num_columns(3).striped(true).show(ui, |ui| {
                ui.strong("module");
                ui.strong("uuid");
                ui.strong("resolved to");
                ui.end_row();
                for d in &p.required_modules {
                    let found = m.w.images.iter().find(|im| im.header.pkg.as_ref().is_some_and(|pk| pk.worklist.iter().any(|x| x.name == d.name && x.build_id_lo == d.build_id_lo)));
                    match found {
                        Some(im) if cfg!(not(target_arch = "wasm32")) => {
                            if ui.link(&d.name).on_hover_text(format!("open {} in a new tab", im.path.display())).clicked() {
                                open = Some(image_load(m, im));
                            }
                        }
                        _ => {
                            ui.label(&d.name);
                        }
                    }
                    ui.label(RichText::new(&d.uuid).monospace().weak());
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
        if open.is_some() {
            self.open_request = open;
        }
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
        let mut close = false;
        ui.horizontal(|ui| {
            ui.strong("Inspector");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button("×").clicked();
            });
        });
        if close {
            self.sel = None;
            return;
        }
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
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!(
                    "{} @ {}{}{}",
                    w.img(o.img).display_name(),
                    if o.cst { "const+" } else { "" },
                    o.off,
                    size.map(|s| format!("  ·  {s} bytes")).unwrap_or_default()
                )).weak().monospace());
                let im = w.img(o.img);
                if o.img != w.target && im.header.pkg.is_some() && cfg!(not(target_arch = "wasm32"))
                    && ui.small_button(format!("Open {}", im.display_name())).on_hover_text("open this image in a new tab").clicked()
                {
                    self.open_request = Some(image_load(m, im));
                }
            });
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
    let r = ui.add(egui::Label::new(RichText::new(text).color(color)).selectable(false).truncate().sense(Sense::click()));
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn clicking_table_text_selects_the_row() {
        use egui_kittest::kittest::Queryable;

        let mut harness = egui_kittest::Harness::builder()
            .with_size([600.0, 200.0])
            .build_ui_state(|ui, clicked| {
                clickable_table(ui)
                    .column(Column::exact(100.0))
                    .column(Column::remainder())
                    .body(|body| {
                        body.rows(20.0, 1, |mut row| {
                            row.col(|ui| { ui.label(RichText::new("1234").monospace()); });
                            row.col(|ui| { ui.label(RichText::new("Example.f(Int64)").italics()); });
                            if row.response().on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                *clicked += 1;
                            }
                        });
                    });
            }, 0);
        for label in ["Example.f(Int64)", "1234"] {
            harness.get_by_label(label).hover();
            harness.run();
            assert_eq!(harness.output().platform_output.cursor_icon, egui::CursorIcon::PointingHand);
            harness.get_by_label(label).click();
            harness.run();
        }
        assert_eq!(*harness.state(), 2);
    }

    #[test]
    fn opening_an_open_file_switches_to_its_tab() {
        let mut harness = egui_kittest::Harness::builder().build_eframe(|cc| App::new(cc, None));
        let ctx = harness.ctx.clone();
        let app = harness.state_mut();
        app.open(&ctx, Load::Paths(vec!["/nonexistent/A.ji".into()], None));
        app.open(&ctx, Load::Paths(vec!["/nonexistent/B.ji".into()], None));
        assert_eq!((app.docs.len(), app.active), (2, 1));
        app.docs[0].obj_filter = "kept".into();
        app.open(&ctx, Load::Paths(vec!["/nonexistent/A.ji".into()], None));
        assert_eq!((app.docs.len(), app.active), (2, 0));
        // A different system image is a different view of the file.
        app.open(&ctx, Load::Paths(vec!["/nonexistent/A.ji".into()], Some("/nonexistent/sys.so".into())));
        assert_eq!((app.docs.len(), app.active), (3, 2));
        assert!(app.docs[2].obj_filter.is_empty());
    }

    #[test]
    fn closing_tabs_keeps_selection_valid() {
        let mut harness = egui_kittest::Harness::builder().build_eframe(|cc| App::new(cc, None));
        let app = harness.state_mut();
        for t in ["a", "b", "c"] {
            app.push(Doc::new(State::Failed(String::new()), t.into(), None));
        }
        app.active = 1;
        app.close(0);
        assert_eq!(app.doc().unwrap().title, "b");
        app.close(1);
        assert_eq!(app.doc().unwrap().title, "b");
        app.close(0);
        assert!(app.doc().is_none());
        app.close(0);
    }

    #[test]
    fn back_and_forward_restore_views() {
        let mut d = Doc::new(State::Failed(String::new()), "a".into(), None);
        let o = Obj { img: 0, off: 8, cst: false };
        d.record();
        d.tab = Tab::Heap;
        d.record();
        d.record();
        d.tab = Tab::Objects;
        d.obj_exact = Some(3);
        d.select(o);
        d.record();
        d.go(true);
        assert!(d.tab == Tab::Heap && d.obj_exact.is_none() && d.selected().is_none());
        d.go(false);
        assert!(d.tab == Tab::Objects && d.obj_exact == Some(3) && d.selected() == Some(o));
        d.go(false);
        assert!(d.tab == Tab::Objects);
        // Navigating after going back drops the forward entries.
        d.go(true);
        d.go(true);
        d.tab = Tab::Methods;
        d.record();
        assert!(!d.can_go(false));
        d.go(true);
        assert!(d.tab == Tab::Overview && !d.can_go(true));
    }

    #[test]
    fn disconnected_loader_displays_failure() {
        let mut harness = egui_kittest::Harness::builder().build_eframe(|cc| App::new(cc, None));
        let (tx, rx) = mpsc::channel();
        harness.state_mut().push(Doc::new(State::Loading(rx, "image".into()), "image".into(), None));
        drop(tx);
        harness.step();
        assert!(matches!(&harness.state().docs[0].state, State::Failed(e) if e.contains("stopped unexpectedly")));
    }
}
