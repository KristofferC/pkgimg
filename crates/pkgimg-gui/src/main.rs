mod app;
#[cfg(not(target_arch = "wasm32"))]
mod browser;
mod model;

use anyhow::Result;
use pkgimg_core::{Image, World};
use std::time::Duration;

/// Load the requested images and compute the model (runs off the UI thread on native).
pub fn load(l: app::Load) -> Result<model::Model> {
    let t0 = web_time_now();
    let w = match l {
        app::Load::Paths(paths, sysimage) => {
            let (first, rest) = paths.split_first().ok_or_else(|| anyhow::anyhow!("no file"))?;
            if rest.is_empty() {
                World::open(first, pkgimg_core::Options { sysimage, depots: vec![], verbose: false })?
            } else {
                let others = rest.iter().map(|p| Image::open(p)).collect::<Result<Vec<_>>>()?;
                World::from_images(Image::open(first)?, others)
            }
        }
        app::Load::Bytes(files) => {
            // Pair .ji files with the native library of the same stem; the target is the
            // first package image that is not a dependency of another one.
            use pkgimg_core::heap::Blob;
            let mut jis = vec![];
            let mut natives = std::collections::HashMap::new();
            for (name, bytes) in files {
                let stem = name.rsplit_once('.').map_or(name.clone(), |(s, _)| s.to_string());
                if name.ends_with(".ji") {
                    jis.push((stem, name, bytes));
                } else {
                    natives.insert(stem, (name, bytes));
                }
            }
            let mut images = vec![];
            for (stem, name, bytes) in jis {
                let nat = natives.remove(&stem);
                let (np, nb) = match nat {
                    Some((n, b)) => (Some(n.into()), Some(Blob::from_vec(b))),
                    None => (None, None),
                };
                images.push(Image::from_bytes(name.into(), Blob::from_vec(bytes), np, nb)?);
            }
            for (_, (name, bytes)) in natives {
                // Remaining native libraries: system images (embedded heap).
                images.push(Image::from_bytes(name.into(), Blob::from_vec(bytes), None, None)?);
            }
            let headers: Vec<_> = images.iter().map(|im| &im.header).collect();
            let ti = dropped_target(&headers)
                .ok_or_else(|| anyhow::anyhow!("no root package image (.ji) among the dropped files"))?;
            let target = images.swap_remove(ti);
            World::from_images(target, images)
        }
    };
    Ok(model::Model::build(w, web_time_now().saturating_sub(t0)))
}

/// Pick a package that is not required by another dropped package, preserving drop order.
fn dropped_target(headers: &[&pkgimg_core::header::Header]) -> Option<usize> {
    headers.iter().enumerate().position(|(i, header)| {
        let Some(pkg) = &header.pkg else { return false };
        !headers.iter().enumerate().any(|(j, other)| {
            i != j && other.pkg.as_ref().is_some_and(|other| {
                other.required_modules.iter().any(|dep| {
                    pkg.worklist.iter().any(|module| {
                        module.name == dep.name && module.uuid == dep.uuid
                            && module.build_id_lo == dep.build_id_lo
                            && (dep.build_id_hi == 0 || dep.build_id_hi == header.base.checksum)
                    })
                })
            })
        })
    })
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use pkgimg_core::header::{self, ModuleId, PkgHeader};

    fn package(name: &str, dependencies: &[&str]) -> header::Header {
        let module = |name: &str| ModuleId {
            name: name.into(), uuid: name.into(), build_id_hi: 0, build_id_lo: 1,
        };
        let mut h = header::raw_sysimage_header("Linux", "x86_64");
        h.pkg = Some(PkgHeader {
            cache_flags: header::CacheFlags {
                raw: 0, use_pkgimages: true, debug_level: 0, check_bounds: 0,
                inline: true, opt_level: 2,
            },
            coverage: 0, syntax_version: 0, worklist: vec![module(name)],
            includes: vec![], requires: vec![], preferences: String::new(), srctext_pos: 0,
            required_modules: dependencies.iter().map(|name| module(name)).collect(),
            clone_targets: vec![],
        });
        h
    }

    #[test]
    fn dropped_package_selection_uses_dependency_graph() {
        let dependency = package("Dependency", &[]);
        let intermediate = package("Intermediate", &["Dependency"]);
        let target = package("Target", &["Intermediate"]);
        let sys = header::raw_sysimage_header("Linux", "x86_64");
        assert_eq!(dropped_target(&[&sys, &dependency, &intermediate, &target]), Some(3));
        assert_eq!(dropped_target(&[&target, &dependency]), Some(0));
        assert_eq!(dropped_target(&[&sys]), None);
    }

    #[test]
    fn different_dependency_build_does_not_hide_package() {
        let mut dependency = package("Dependency", &[]);
        let target = package("Target", &["Dependency"]);
        dependency.pkg.as_mut().unwrap().worklist[0].build_id_lo = 2;
        assert_eq!(dropped_target(&[&dependency, &target]), Some(0));
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn web_time_now() -> Duration {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
fn web_time_now() -> Duration {
    Duration::from_secs_f64(js_sys::Date::now() / 1000.0)
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result {
    let paths: Vec<std::path::PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    let initial = (!paths.is_empty()).then_some(app::Load::Paths(paths, None));
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 900.0]).with_title("pkgimg"),
        ..Default::default()
    };
    eframe::run_native("pkgimg", opts, Box::new(|cc| Ok(Box::new(app::App::new(cc, initial)))))
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use wasm_bindgen::JsCast;
    wasm_bindgen_futures::spawn_local(async {
        let document = web_sys::window().unwrap().document().unwrap();
        let canvas = document.get_element_by_id("the_canvas_id").unwrap().dyn_into::<web_sys::HtmlCanvasElement>().unwrap();
        eframe::WebRunner::new()
            .start(canvas, eframe::WebOptions::default(), Box::new(|cc| Ok(Box::new(app::App::new(cc, None)))))
            .await
            .expect("failed to start eframe");
    });
}

#[cfg(test)]
mod shots {
    use super::app;
    use egui_kittest::kittest::Queryable;

    /// Render every tab of `$PKGIMG_SHOT_FILE` into `$PKGIMG_SHOT_DIR` (run with --ignored).
    #[test]
    #[ignore]
    fn screenshots() {
        let file = std::env::var("PKGIMG_SHOT_FILE").expect("PKGIMG_SHOT_FILE");
        let dir = std::path::PathBuf::from(std::env::var("PKGIMG_SHOT_DIR").expect("PKGIMG_SHOT_DIR"));
        let dark = std::env::var("PKGIMG_SHOT_DARK").is_ok();
        let mut h = egui_kittest::Harness::builder()
            .with_size([1500.0, 900.0])
            .wgpu()
            .build_eframe(|cc| {
                cc.egui_ctx.set_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light });
                app::App::new(cc, Some(app::Load::Paths(vec![file.clone().into()], None)))
            });
        for _ in 0..1200 {
            h.step();
            if h.state().is_ready() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(h.state().is_ready(), "image did not load");
        let save = |h: &mut egui_kittest::Harness<app::App>, name: &str| {
            h.remove_cursor();
            h.run_steps(4);
            let img = h.render().expect("render");
            img.save(dir.join(format!("{name}.png"))).unwrap();
        };
        save(&mut h, "overview");
        for (tab, name) in [("Heap", "heap"), ("Objects", "objects"), ("Code instances", "compiled"), ("Methods", "methods"), ("Sources", "sources"), ("Dependencies", "deps")] {
            h.get_by_label(tab).click();
            save(&mut h, name);
        }
        h.get_by_label("Code instances").click();
        h.state_mut().select_largest_ci();
        save(&mut h, "inspector");
    }

    /// Insights, following an insight link, and opening a dependency in a second tab
    /// (run with --ignored; `$PKGIMG_SHOT_FUNC` is a function listed in the insights and
    /// `$PKGIMG_SHOT_DEP` a dependency of the image).
    #[test]
    #[ignore]
    fn insights_and_tabs() {
        let file = std::env::var("PKGIMG_SHOT_FILE").expect("PKGIMG_SHOT_FILE");
        let dir = std::path::PathBuf::from(std::env::var("PKGIMG_SHOT_DIR").expect("PKGIMG_SHOT_DIR"));
        let dep = std::env::var("PKGIMG_SHOT_DEP").expect("PKGIMG_SHOT_DEP");
        let func = std::env::var("PKGIMG_SHOT_FUNC").expect("PKGIMG_SHOT_FUNC");
        let mut h = egui_kittest::Harness::builder()
            .with_size([1500.0, 900.0])
            .wgpu()
            .build_eframe(|cc| app::App::new(cc, Some(app::Load::Paths(vec![file.clone().into()], None))));
        let wait = |h: &mut egui_kittest::Harness<app::App>| {
            for _ in 0..1200 {
                h.step();
                if h.state().is_ready() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert!(h.state().is_ready(), "image did not load");
            h.run_steps(4);
        };
        let save = |h: &mut egui_kittest::Harness<app::App>, name: &str| {
            h.remove_cursor();
            h.run_steps(4);
            h.render().expect("render").save(dir.join(format!("{name}.png"))).unwrap();
        };
        wait(&mut h);
        save(&mut h, "overview");
        h.get_by_label_contains("Insights (").click();
        save(&mut h, "insights");
        h.get_by_label(&func).click();
        save(&mut h, "methods-of-function");
        h.get_by_label("function").click();
        save(&mut h, "methods-by-function");
        h.get_by_label("Dependencies").click();
        save(&mut h, "deps");
        let ctx = h.ctx.clone();
        assert!(h.state_mut().open_dependency(&ctx, &dep), "dependency {dep} not resolved");
        wait(&mut h);
        save(&mut h, "dependency-tab");
    }

    /// Grouped tables must not reorder between frames (run with --ignored).
    #[test]
    #[ignore]
    fn group_table_is_stable() {
        let file = std::env::var("PKGIMG_SHOT_FILE").expect("PKGIMG_SHOT_FILE");
        let mut h = egui_kittest::Harness::builder()
            .with_size([1500.0, 900.0])
            .wgpu()
            .build_eframe(|cc| app::App::new(cc, Some(app::Load::Paths(vec![file.clone().into()], None))));
        for _ in 0..1200 {
            h.step();
            if h.state().is_ready() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        h.get_by_label("Code instances").click();
        h.run_steps(3);
        // Group by file and sort ascending by native size: the many ties are on screen.
        h.get_by_label("file").click();
        h.run_steps(3);
        h.get_by_label("native ⏷").click();
        h.run_steps(3);
        let a = h.render().unwrap();
        h.run_steps(5);
        let b = h.render().unwrap();
        assert!(a == b, "group table changed between frames");
    }

    /// Render the file browser into `$PKGIMG_SHOT_DIR/browser.png` (run with --ignored).
    #[test]
    #[ignore]
    fn browser_screenshot() {
        let dir = std::path::PathBuf::from(std::env::var("PKGIMG_SHOT_DIR").expect("PKGIMG_SHOT_DIR"));
        let mut h = egui_kittest::Harness::builder()
            .with_size([1500.0, 900.0])
            .wgpu()
            .build_eframe(|cc| app::App::new(cc, None));
        for _ in 0..600 {
            h.step();
            if h.state_mut().browser_mut().scanned() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        h.run_steps(2);
        h.render().unwrap().save(dir.join("browser-all.png")).unwrap();
        h.state_mut().browser_mut().set_filter("Dates");
        h.run_steps(4);
        h.render().unwrap().save(dir.join("browser.png")).unwrap();
    }
}
