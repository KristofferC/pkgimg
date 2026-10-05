//! Native file browser: discovered cache files, filters, recents.

use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use pkgimg_core::discover::{self, CacheFile, Discovery, HeaderSummary, RootKind};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::SystemTime;

/// What the user picked: the cache file and a system image hint.
pub struct Pick {
    pub ji: PathBuf,
    pub sysimage: Option<PathBuf>,
}

pub struct Browser {
    scan: Option<mpsc::Receiver<Discovery>>,
    disc: Option<Discovery>,
    filter: String,
    julia: Option<String>,
    root: Option<usize>,
    sort_col: usize,
    sort_desc: bool,
    order: Vec<usize>,
    order_key: String,
    summaries: HashMap<PathBuf, Option<HeaderSummary>>,
    extra_dirs: Vec<PathBuf>,
    dir_input: String,
    pub recent: Vec<PathBuf>,
    focus_filter: bool,
}

fn recent_file() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("pkgimg").join("recent"))
}

fn home_short(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    match std::env::var("HOME") {
        Ok(h) if s.starts_with(&h) => format!("~{}", &s[h.len()..]),
        _ => s,
    }
}

fn age(t: SystemTime) -> String {
    let s = SystemTime::now().duration_since(t).map(|d| d.as_secs()).unwrap_or(0);
    match s {
        s if s < 120 => format!("{s}s ago"),
        s if s < 7200 => format!("{}m ago", s / 60),
        s if s < 172800 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

fn size(b: u64) -> String {
    match b {
        0 => "-".into(),
        b if b >= 10 << 20 => format!("{:.1} MiB", b as f64 / (1 << 20) as f64),
        b => format!("{:.0} KiB", (b as f64 / 1024.0).ceil()),
    }
}

/// Parse "1.14" / "v1.14" / "v1.6" for numeric sorting.
fn ver_key(v: &str) -> (u32, u32) {
    let mut it = v.trim_start_matches('v').split('.');
    (it.next().and_then(|x| x.parse().ok()).unwrap_or(0), it.next().and_then(|x| x.parse().ok()).unwrap_or(0))
}

impl Browser {
    pub fn new() -> Browser {
        let recent = recent_file()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .map(|s| s.lines().map(PathBuf::from).filter(|p| p.exists()).collect())
            .unwrap_or_default();
        let mut b = Browser {
            scan: None, disc: None, filter: String::new(), julia: None, root: None,
            sort_col: 3, sort_desc: true, order: vec![], order_key: String::new(),
            summaries: HashMap::new(), extra_dirs: vec![], dir_input: String::new(), recent,
            focus_filter: true,
        };
        b.rescan();
        b
    }

    pub fn rescan(&mut self) {
        let (tx, rx) = mpsc::channel();
        let extra = self.extra_dirs.clone();
        std::thread::spawn(move || {
            let _ = tx.send(discover::discover(&extra));
        });
        self.scan = Some(rx);
        self.order_key.clear();
    }

    #[cfg(test)]
    pub fn scanned(&self) -> bool {
        self.disc.is_some()
    }

    #[cfg(test)]
    pub fn set_filter(&mut self, f: &str) {
        self.filter = f.into();
        self.focus_filter = false;
    }

    pub fn remember(&mut self, p: &std::path::Path) {
        self.recent.retain(|r| r != p);
        self.recent.insert(0, p.to_path_buf());
        self.recent.truncate(20);
        if let Some(f) = recent_file() {
            let _ = std::fs::create_dir_all(f.parent().unwrap());
            let _ = std::fs::write(f, self.recent.iter().map(|p| p.display().to_string() + "\n").collect::<String>());
        }
        self.focus_filter = true;
    }

    fn summary(&mut self, p: &PathBuf) -> Option<&HeaderSummary> {
        self.summaries.entry(p.clone()).or_insert_with(|| discover::read_summary(p)).as_ref()
    }

    /// Sysimage hint for a path: the install it lives under, if any.
    fn sysimage_for_path(&self, p: &std::path::Path) -> Option<PathBuf> {
        let d = self.disc.as_ref()?;
        d.roots.iter().filter(|r| r.kind == RootKind::Install && p.starts_with(&r.path)).find_map(|r| r.sysimage.clone())
    }

    pub fn ui(&mut self, ui: &mut Ui) -> Option<Pick> {
        if let Some(rx) = &self.scan
            && let Ok(d) = rx.try_recv()
        {
            self.disc = Some(d);
            self.scan = None;
            self.order_key.clear();
        }
        let mut pick = None;
        ui.horizontal(|ui| {
            ui.heading("Open a cache file");
            if self.scan.is_some() {
                ui.spinner();
                ui.label(RichText::new("scanning depots and Julia installations…").weak());
            } else if let Some(d) = &self.disc {
                ui.label(RichText::new(format!("{} cache files in {} locations", d.caches.len(), d.roots.len())).weak());
            }
            if ui.button("⟳ Rescan").clicked() {
                self.rescan();
            }
        });
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("package name…").desired_width(260.0));
            if self.focus_filter {
                r.request_focus();
                self.focus_filter = false;
            }
            // Enter opens the first match
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                if let (Some(&i), Some(d)) = (self.order.first(), &self.disc) {
                    let c = &d.caches[i];
                    pick = Some(Pick { ji: c.ji.clone(), sysimage: discover::sysimage_for(d, c) });
                }
            }
            ui.separator();
            ui.label("Julia");
            if ui.selectable_label(self.julia.is_none(), "all").clicked() {
                self.julia = None;
            }
            if let Some(d) = &self.disc {
                let mut vers: Vec<&str> = d.caches.iter().map(|c| c.julia.as_str()).collect();
                vers.sort_by_key(|v| std::cmp::Reverse(ver_key(v)));
                vers.dedup();
                for v in vers.into_iter().take(10) {
                    if ui.selectable_label(self.julia.as_deref() == Some(v), v).clicked() {
                        self.julia = Some(v.to_string());
                    }
                }
            }
        });
        ui.add_space(4.0);

        // Locations
        egui::Panel::left("locations").resizable(true).default_size(300.0).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if !self.recent.is_empty() {
                    ui.strong("Recent");
                    for p in self.recent.clone().iter().take(8) {
                        let name = p.parent().and_then(|d| d.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        if ui.link(name).on_hover_text(home_short(p)).clicked() {
                            pick = Some(Pick { ji: p.clone(), sysimage: self.sysimage_for_path(p) });
                        }
                    }
                    ui.add_space(8.0);
                }
                ui.strong("Locations");
                if ui.selectable_label(self.root.is_none(), "everything").clicked() {
                    self.root = None;
                }
                if let Some(d) = &self.disc {
                    let mut counts = vec![0usize; d.roots.len()];
                    for c in &d.caches {
                        counts[c.root] += 1;
                    }
                    for (kind, title) in [(RootKind::Depot, "Depots"), (RootKind::Install, "Julia installations"), (RootKind::Custom, "Added folders")] {
                        let rs: Vec<usize> = (0..d.roots.len()).filter(|&i| d.roots[i].kind == kind && counts[i] > 0).collect();
                        if rs.is_empty() {
                            continue;
                        }
                        ui.label(RichText::new(title).weak());
                        for i in rs {
                            let label = format!("{}  ({})", discover::root_label(&d.roots[i]), counts[i]);
                            if ui.selectable_label(self.root == Some(i), label).on_hover_text(home_short(&d.roots[i].path)).clicked() {
                                self.root = Some(i);
                            }
                        }
                    }
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.dir_input).hint_text("add folder…").desired_width(200.0));
                    if ui.button("Add").clicked() && !self.dir_input.trim().is_empty() {
                        let p = crate::app::shellexpand(&self.dir_input);
                        // A .ji path opens directly.
                        if p.extension().is_some_and(|e| e == "ji" || e == "so" || e == "dylib" || e == "dll") && p.is_file() {
                            pick = Some(Pick { sysimage: self.sysimage_for_path(&p), ji: p });
                        } else {
                            self.extra_dirs.push(p);
                            self.rescan();
                        }
                        self.dir_input.clear();
                    }
                });
            });
        });

        let Some(d) = self.disc.take() else {
            return pick;
        };
        let key = format!("{}|{:?}|{:?}|{}|{}", self.filter, self.julia, self.root, self.sort_col, self.sort_desc);
        if key != self.order_key {
            let f = self.filter.to_lowercase();
            let mut order: Vec<usize> = (0..d.caches.len())
                .filter(|&i| {
                    let c = &d.caches[i];
                    (f.is_empty() || c.package.to_lowercase().contains(&f))
                        && self.julia.as_ref().is_none_or(|j| &c.julia == j)
                        && self.root.is_none_or(|r| c.root == r)
                })
                .collect();
            let cs = &d.caches;
            let exact = |c: &CacheFile| !f.is_empty() && c.package.to_lowercase() == f;
            order.sort_by(|&a, &b| {
                let (x, y) = (&cs[a], &cs[b]);
                let o = match self.sort_col {
                    0 => x.package.to_lowercase().cmp(&y.package.to_lowercase()),
                    1 => ver_key(&x.julia).cmp(&ver_key(&y.julia)),
                    2 => x.root.cmp(&y.root),
                    3 => x.modified.cmp(&y.modified),
                    4 => x.ji_size.cmp(&y.ji_size),
                    _ => x.native_size.cmp(&y.native_size),
                };
                // Exact name matches first, then the chosen order.
                exact(y).cmp(&exact(x)).then(if self.sort_desc { o.reverse() } else { o })
            });
            self.order = order;
            self.order_key = key;
        }
        let order = self.order.clone();
        let (mut sc, mut sd) = (self.sort_col, self.sort_desc);
        let mut header = |ui: &mut Ui, label: &str, i: usize, desc: bool| {
            let arrow = if sc == i { if sd { " ⏷" } else { " ⏶" } } else { "" };
            if ui.add(egui::Button::new(RichText::new(format!("{label}{arrow}")).strong()).frame(false)).clicked() {
                if sc == i { sd = !sd } else { sc = i; sd = desc }
            }
        };
        let mut hovered = false;
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::initial(220.0).clip(true).resizable(true))
            .column(Column::exact(60.0))
            .column(Column::initial(260.0).clip(true).resizable(true))
            .column(Column::exact(80.0))
            .column(Column::exact(80.0))
            .column(Column::exact(80.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                h.col(|ui| header(ui, "package", 0, false));
                h.col(|ui| header(ui, "julia", 1, true));
                h.col(|ui| header(ui, "location", 2, false));
                h.col(|ui| header(ui, "modified", 3, true));
                h.col(|ui| header(ui, ".ji", 4, true));
                h.col(|ui| header(ui, "native", 5, true));
                h.col(|ui| { ui.strong("built by"); });
            })
            .body(|body| {
                body.rows(20.0, order.len(), |mut row| {
                    let c = &d.caches[order[row.index()]];
                    let r = &d.roots[c.root];
                    let ok = self.summary(&c.ji).is_some_and(|s| s.supported);
                    row.col(|ui| { ui.label(if ok { RichText::new(&c.package).strong() } else { RichText::new(&c.package).weak() }); });
                    row.col(|ui| { ui.label(&c.julia); });
                    row.col(|ui| { ui.label(RichText::new(discover::root_label(r)).weak()); });
                    row.col(|ui| { ui.label(age(c.modified)); });
                    row.col(|ui| { ui.label(RichText::new(size(c.ji_size)).monospace()); });
                    row.col(|ui| { ui.label(RichText::new(size(c.native_size)).monospace()); });
                    row.col(|ui| {
                        // Header facts are read lazily, only for visible rows.
                        let s = self.summary(&c.ji).map(|s| {
                            if !s.supported {
                                return format!("{} (format v{}, not supported)", s.julia_version, s.format_version);
                            }
                            let commit = s.git_commit.as_deref().map(|c| &c[..c.len().min(10)]).unwrap_or("");
                            format!("{} {}", s.julia_version, commit)
                        });
                        ui.label(RichText::new(s.unwrap_or_else(|| "unreadable".into())).weak());
                    });
                    let resp = row.response().on_hover_text(home_short(&c.ji));
                    if resp.hovered() {
                        hovered = true;
                    }
                    if resp.clicked() {
                        pick = Some(Pick { ji: c.ji.clone(), sysimage: discover::sysimage_for(&d, c) });
                    }
                });
            });
        (self.sort_col, self.sort_desc) = (sc, sd);
        if hovered {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        self.disc = Some(d);
        pick
    }
}
