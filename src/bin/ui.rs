use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use mhrv_rs::cert_installer::install_ca;
use mhrv_rs::config::{Config, ScriptId};
use mhrv_rs::data_dir;
use mhrv_rs::domain_fronter::DomainFronter;
use mhrv_rs::mitm::{MitmCertManager, CA_CERT_FILE};
use mhrv_rs::proxy_server::ProxyServer;
use mhrv_rs::{scan_ips, test_cmd};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const WIN_WIDTH: f32 = 520.0;
const WIN_HEIGHT: f32 = 680.0;
const LOG_MAX: usize = 200;

fn main() -> eframe::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let shared = Arc::new(Shared::default());
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Cmd>();

    let shared_bg = shared.clone();
    std::thread::Builder::new()
        .name("mhrv-bg".into())
        .spawn(move || background_thread(shared_bg, cmd_rx))
        .expect("failed to spawn background thread");

    let form = load_form();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([WIN_WIDTH, WIN_HEIGHT])
            .with_min_inner_size([420.0, 540.0])
            .with_title(format!("mhrv-rs {}", VERSION)),
        ..Default::default()
    };

    eframe::run_native(
        "mhrv-rs",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App {
                shared,
                cmd_tx,
                form,
                last_poll: Instant::now(),
                toast: None,
            }))
        }),
    )
}

#[derive(Default)]
struct Shared {
    state: Mutex<UiState>,
}

#[derive(Default)]
struct UiState {
    running: bool,
    started_at: Option<Instant>,
    last_stats: Option<mhrv_rs::domain_fronter::StatsSnapshot>,
    log: VecDeque<String>,
    ca_trusted: Option<bool>,
    last_test_ok: Option<bool>,
    last_test_msg: String,
}

enum Cmd {
    Start(Config),
    Stop,
    Test(Config),
    InstallCa,
    CheckCaTrusted,
    PollStats,
}

struct App {
    shared: Arc<Shared>,
    cmd_tx: Sender<Cmd>,
    form: FormState,
    last_poll: Instant,
    toast: Option<(String, Instant)>,
}

#[derive(Clone)]
struct FormState {
    script_id: String,
    auth_key: String,
    google_ip: String,
    front_domain: String,
    listen_host: String,
    listen_port: String,
    socks5_port: String,
    log_level: String,
    verify_ssl: bool,
    show_auth_key: bool,
}

fn load_form() -> FormState {
    let path = data_dir::config_path();
    let cwd = PathBuf::from("config.json");
    let existing = if path.exists() {
        Config::load(&path).ok()
    } else if cwd.exists() {
        Config::load(&cwd).ok()
    } else {
        None
    };
    if let Some(c) = existing {
        let sid = match &c.script_id {
            Some(ScriptId::One(s)) => s.clone(),
            Some(ScriptId::Many(v)) => v.join(", "),
            None => match &c.script_ids {
                Some(ScriptId::One(s)) => s.clone(),
                Some(ScriptId::Many(v)) => v.join(", "),
                None => String::new(),
            },
        };
        FormState {
            script_id: sid,
            auth_key: c.auth_key,
            google_ip: c.google_ip,
            front_domain: c.front_domain,
            listen_host: c.listen_host,
            listen_port: c.listen_port.to_string(),
            socks5_port: c.socks5_port.map(|p| p.to_string()).unwrap_or_default(),
            log_level: c.log_level,
            verify_ssl: c.verify_ssl,
            show_auth_key: false,
        }
    } else {
        FormState {
            script_id: String::new(),
            auth_key: String::new(),
            google_ip: "216.239.38.120".into(),
            front_domain: "www.google.com".into(),
            listen_host: "127.0.0.1".into(),
            listen_port: "8085".into(),
            socks5_port: "8086".into(),
            log_level: "info".into(),
            verify_ssl: true,
            show_auth_key: false,
        }
    }
}

impl FormState {
    fn to_config(&self) -> Result<Config, String> {
        if self.script_id.trim().is_empty() {
            return Err("Apps Script ID is required".into());
        }
        if self.auth_key.trim().is_empty() {
            return Err("Auth key is required".into());
        }
        let listen_port: u16 = self
            .listen_port
            .parse()
            .map_err(|_| "HTTP port must be a number".to_string())?;
        let socks5_port: Option<u16> = if self.socks5_port.trim().is_empty() {
            None
        } else {
            Some(
                self.socks5_port
                    .parse()
                    .map_err(|_| "SOCKS5 port must be a number".to_string())?,
            )
        };
        let ids: Vec<String> = self
            .script_id
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let script_id = if ids.len() == 1 {
            Some(ScriptId::One(ids[0].clone()))
        } else {
            Some(ScriptId::Many(ids))
        };
        Ok(Config {
            mode: "apps_script".into(),
            google_ip: self.google_ip.trim().to_string(),
            front_domain: self.front_domain.trim().to_string(),
            script_id,
            script_ids: None,
            auth_key: self.auth_key.clone(),
            listen_host: self.listen_host.trim().to_string(),
            listen_port,
            socks5_port,
            log_level: self.log_level.trim().to_string(),
            verify_ssl: self.verify_ssl,
            hosts: std::collections::HashMap::new(),
            enable_batching: false,
        })
    }
}

fn save_config(cfg: &Config) -> Result<PathBuf, String> {
    let path = data_dir::config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&ConfigWire::from(cfg))
        .map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(serde::Serialize)]
struct ConfigWire<'a> {
    mode: &'a str,
    google_ip: &'a str,
    front_domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_id: Option<ScriptIdWire<'a>>,
    auth_key: &'a str,
    listen_host: &'a str,
    listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    socks5_port: Option<u16>,
    log_level: &'a str,
    verify_ssl: bool,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    hosts: &'a std::collections::HashMap<String, String>,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum ScriptIdWire<'a> {
    One(&'a str),
    Many(Vec<&'a str>),
}

impl<'a> From<&'a Config> for ConfigWire<'a> {
    fn from(c: &'a Config) -> Self {
        let script_id = c.script_id.as_ref().map(|s| match s {
            ScriptId::One(v) => ScriptIdWire::One(v.as_str()),
            ScriptId::Many(v) => ScriptIdWire::Many(v.iter().map(String::as_str).collect()),
        });
        ConfigWire {
            mode: c.mode.as_str(),
            google_ip: c.google_ip.as_str(),
            front_domain: c.front_domain.as_str(),
            script_id,
            auth_key: c.auth_key.as_str(),
            listen_host: c.listen_host.as_str(),
            listen_port: c.listen_port,
            socks5_port: c.socks5_port,
            log_level: c.log_level.as_str(),
            verify_ssl: c.verify_ssl,
            hosts: &c.hosts,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if self.last_poll.elapsed() > Duration::from_millis(700) {
            let _ = self.cmd_tx.send(Cmd::PollStats);
            self.last_poll = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(500));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.style_mut().spacing.item_spacing = egui::vec2(8.0, 6.0);

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("mhrv-rs  {}", VERSION))
                    .size(16.0));
                ui.add_space(8.0);
                let running = self.shared.state.lock().unwrap().running;
                let dot = if running { "running" } else { "stopped" };
                let color = if running { egui::Color32::from_rgb(70, 170, 100) } else { egui::Color32::from_rgb(170, 90, 90) };
                ui.label(egui::RichText::new(dot).color(color).monospace());
            });

            ui.separator();

            // Config form.
            egui::Grid::new("cfg")
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Apps Script ID");
                    ui.add(egui::TextEdit::singleline(&mut self.form.script_id)
                        .desired_width(f32::INFINITY));
                    ui.end_row();

                    ui.label("Auth key");
                    ui.horizontal(|ui| {
                        let te = egui::TextEdit::singleline(&mut self.form.auth_key)
                            .password(!self.form.show_auth_key)
                            .desired_width(f32::INFINITY);
                        ui.add(te);
                    });
                    ui.end_row();

                    ui.label("Google IP");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.form.google_ip);
                        if ui.button("scan").on_hover_text(
                            "Try several known Google frontend IPs and report which are reachable (results printed to stdout/terminal)"
                        ).clicked() {
                            if let Ok(cfg) = self.form.to_config() {
                                let _ = self.cmd_tx.send(Cmd::Test(cfg.clone()));
                                self.toast = Some(("Scan started — check terminal for full results".into(), Instant::now()));
                            }
                        }
                    });
                    ui.end_row();

                    ui.label("Front domain");
                    ui.add(egui::TextEdit::singleline(&mut self.form.front_domain)
                        .desired_width(f32::INFINITY));
                    ui.end_row();

                    ui.label("Listen host");
                    ui.add(egui::TextEdit::singleline(&mut self.form.listen_host)
                        .desired_width(f32::INFINITY));
                    ui.end_row();

                    ui.label("HTTP port");
                    ui.add(egui::TextEdit::singleline(&mut self.form.listen_port).desired_width(80.0));
                    ui.end_row();

                    ui.label("SOCKS5 port");
                    ui.add(egui::TextEdit::singleline(&mut self.form.socks5_port).desired_width(80.0));
                    ui.end_row();

                    ui.label("Log level");
                    egui::ComboBox::from_id_source("loglevel")
                        .selected_text(&self.form.log_level)
                        .show_ui(ui, |ui| {
                            for lvl in ["warn", "info", "debug", "trace"] {
                                ui.selectable_value(&mut self.form.log_level, lvl.into(), lvl);
                            }
                        });
                    ui.end_row();

                    ui.label("");
                    ui.checkbox(&mut self.form.verify_ssl, "Verify TLS server certificate (recommended)");
                    ui.end_row();

                    ui.label("");
                    ui.checkbox(&mut self.form.show_auth_key, "Show auth key");
                    ui.end_row();
                });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Save config").clicked() {
                    match self.form.to_config().and_then(|c| save_config(&c)) {
                        Ok(p) => self.toast = Some((format!("Saved to {}", p.display()), Instant::now())),
                        Err(e) => self.toast = Some((format!("Save failed: {}", e), Instant::now())),
                    }
                }
                ui.small(format!("location: {}", data_dir::config_path().display()));
            });

            ui.separator();

            // Status + stats
            let (running, started_at, stats, ca_trusted, last_test_msg) = {
                let s = self.shared.state.lock().unwrap();
                (s.running, s.started_at, s.last_stats, s.ca_trusted, s.last_test_msg.clone())
            };

            ui.horizontal(|ui| {
                if running {
                    let up = started_at.map(|t| t.elapsed()).unwrap_or_default();
                    ui.label(egui::RichText::new(format!(
                        "Status: running  (uptime {})", fmt_duration(up)
                    )).strong());
                } else {
                    ui.label(egui::RichText::new("Status: stopped").strong());
                }
            });

            if let Some(s) = stats {
                egui::Grid::new("stats").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                    ui.label("relay calls");
                    ui.label(egui::RichText::new(s.relay_calls.to_string()).monospace());
                    ui.end_row();
                    ui.label("failures");
                    ui.label(egui::RichText::new(s.relay_failures.to_string()).monospace());
                    ui.end_row();
                    ui.label("coalesced");
                    ui.label(egui::RichText::new(s.coalesced.to_string()).monospace());
                    ui.end_row();
                    ui.label("cache hits / total");
                    ui.label(egui::RichText::new(format!(
                        "{} / {}  ({:.0}%)",
                        s.cache_hits,
                        s.cache_hits + s.cache_misses,
                        s.hit_rate()
                    )).monospace());
                    ui.end_row();
                    ui.label("cache size");
                    ui.label(egui::RichText::new(format!("{} KB", s.cache_bytes / 1024)).monospace());
                    ui.end_row();
                    ui.label("bytes relayed");
                    ui.label(egui::RichText::new(fmt_bytes(s.bytes_relayed)).monospace());
                    ui.end_row();
                    ui.label("active scripts");
                    ui.label(egui::RichText::new(format!(
                        "{} / {}", s.total_scripts - s.blacklisted_scripts, s.total_scripts
                    )).monospace());
                    ui.end_row();
                });
            }

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if !running {
                    if ui.button("Start").clicked() {
                        match self.form.to_config() {
                            Ok(cfg) => {
                                let _ = self.cmd_tx.send(Cmd::Start(cfg));
                            }
                            Err(e) => {
                                self.toast = Some((format!("Cannot start: {}", e), Instant::now()));
                            }
                        }
                    }
                } else if ui.button("Stop").clicked() {
                    let _ = self.cmd_tx.send(Cmd::Stop);
                }

                if ui.button("Test").clicked() {
                    match self.form.to_config() {
                        Ok(cfg) => {
                            let _ = self.cmd_tx.send(Cmd::Test(cfg));
                        }
                        Err(e) => {
                            self.toast = Some((format!("Cannot test: {}", e), Instant::now()));
                        }
                    }
                }

                if ui.button("Install CA").clicked() {
                    let _ = self.cmd_tx.send(Cmd::InstallCa);
                }

                if ui.button("Check CA").clicked() {
                    let _ = self.cmd_tx.send(Cmd::CheckCaTrusted);
                }
            });

            if !last_test_msg.is_empty() {
                ui.small(last_test_msg);
            }
            match ca_trusted {
                Some(true) => { ui.small("CA appears trusted."); },
                Some(false) => { ui.small("CA is NOT trusted in the system store. Click 'Install CA' (may require admin)."); },
                None => {},
            }

            ui.separator();
            ui.label(egui::RichText::new("Recent log").strong());
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let log = self.shared.state.lock().unwrap().log.clone();
                    for line in log.iter() {
                        ui.monospace(line);
                    }
                });

            // Transient toast at the bottom.
            if let Some((msg, t)) = &self.toast {
                if t.elapsed() < Duration::from_secs(5) {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(200, 170, 80), msg);
                } else {
                    self.toast = None;
                }
            }
        });
    }
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn fmt_bytes(b: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = K * K;
    const G: u64 = M * K;
    if b >= G {
        format!("{:.2} GB", b as f64 / G as f64)
    } else if b >= M {
        format!("{:.2} MB", b as f64 / M as f64)
    } else if b >= K {
        format!("{:.1} KB", b as f64 / K as f64)
    } else {
        format!("{} B", b)
    }
}

// ---------- Background thread: owns the tokio runtime + proxy lifecycle ----------

fn background_thread(shared: Arc<Shared>, rx: Receiver<Cmd>) {
    let rt = Runtime::new().expect("failed to create tokio runtime");

    let mut active: Option<(JoinHandle<()>, Arc<AsyncMutex<Option<Arc<DomainFronter>>>>)> = None;

    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Cmd::PollStats) => {
                if let Some((_, fronter_slot)) = &active {
                    let slot = fronter_slot.clone();
                    let shared = shared.clone();
                    rt.spawn(async move {
                        let f = slot.lock().await;
                        if let Some(fronter) = f.as_ref() {
                            let s = fronter.snapshot_stats();
                            shared.state.lock().unwrap().last_stats = Some(s);
                        }
                    });
                }
            }
            Ok(Cmd::Start(cfg)) => {
                if active.is_some() {
                    push_log(&shared, "[ui] already running");
                    continue;
                }
                push_log(&shared, "[ui] starting proxy...");
                let shared2 = shared.clone();
                let fronter_slot: Arc<AsyncMutex<Option<Arc<DomainFronter>>>> =
                    Arc::new(AsyncMutex::new(None));
                let fronter_slot2 = fronter_slot.clone();

                let handle = rt.spawn(async move {
                    let base = data_dir::data_dir();
                    let mitm = match MitmCertManager::new_in(&base) {
                        Ok(m) => m,
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] MITM init failed: {}", e));
                            shared2.state.lock().unwrap().running = false;
                            return;
                        }
                    };
                    let mitm = Arc::new(AsyncMutex::new(mitm));
                    let server = match ProxyServer::new(&cfg, mitm) {
                        Ok(s) => s,
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] proxy build failed: {}", e));
                            shared2.state.lock().unwrap().running = false;
                            return;
                        }
                    };
                    match DomainFronter::new(&cfg) {
                        Ok(f) => {
                            let arc = Arc::new(f);
                            *fronter_slot2.lock().await = Some(arc);
                        }
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] fronter build failed: {}", e));
                        }
                    }
                    {
                        let mut s = shared2.state.lock().unwrap();
                        s.running = true;
                        s.started_at = Some(Instant::now());
                    }
                    push_log(&shared2, &format!(
                        "[ui] listening HTTP {}:{} SOCKS5 {}:{}",
                        cfg.listen_host, cfg.listen_port,
                        cfg.listen_host, cfg.socks5_port.unwrap_or(cfg.listen_port + 1)
                    ));
                    let _ = server.run().await;
                    shared2.state.lock().unwrap().running = false;
                    push_log(&shared2, "[ui] proxy stopped");
                });

                active = Some((handle, fronter_slot));
            }
            Ok(Cmd::Stop) => {
                if let Some((handle, _)) = active.take() {
                    handle.abort();
                    shared.state.lock().unwrap().running = false;
                    shared.state.lock().unwrap().started_at = None;
                    shared.state.lock().unwrap().last_stats = None;
                    push_log(&shared, "[ui] stop requested");
                }
            }
            Ok(Cmd::Test(cfg)) => {
                let shared2 = shared.clone();
                push_log(&shared, "[ui] running test...");
                rt.spawn(async move {
                    let ok = test_cmd::run(&cfg).await;
                    shared2.state.lock().unwrap().last_test_ok = Some(ok);
                    shared2.state.lock().unwrap().last_test_msg = if ok {
                        "Test passed — relay is working.".into()
                    } else {
                        "Test failed — see terminal for details.".into()
                    };
                    push_log(&shared2, &format!("[ui] test result: {}", if ok { "pass" } else { "fail" }));
                    // Also run ip scan on demand (cheap).
                    let _ = scan_ips::run(&cfg).await;
                });
            }
            Ok(Cmd::InstallCa) => {
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    push_log(&shared2, "[ui] installing CA...");
                    let base = data_dir::data_dir();
                    if let Err(e) = MitmCertManager::new_in(&base) {
                        push_log(&shared2, &format!("[ui] CA init failed: {}", e));
                        return;
                    }
                    let ca = base.join(CA_CERT_FILE);
                    match install_ca(&ca) {
                        Ok(()) => {
                            push_log(&shared2, "[ui] CA install ok");
                            shared2.state.lock().unwrap().ca_trusted = Some(true);
                        }
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] CA install failed: {}", e));
                            push_log(&shared2, "[ui] hint: run the terminal binary with sudo/admin: mhrv-rs --install-cert");
                        }
                    }
                });
            }
            Ok(Cmd::CheckCaTrusted) => {
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    let base = data_dir::data_dir();
                    let ca = base.join(CA_CERT_FILE);
                    let trusted = mhrv_rs::cert_installer::is_ca_trusted(&ca);
                    shared2.state.lock().unwrap().ca_trusted = Some(trusted);
                });
            }
            Err(_) => {}
        }

        // Clean up finished task.
        if let Some((handle, _)) = &active {
            if handle.is_finished() {
                active = None;
                shared.state.lock().unwrap().running = false;
            }
        }
    }
}

fn push_log(shared: &Shared, msg: &str) {
    let line = format!(
        "{}  {}",
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Iso8601::DEFAULT).unwrap_or_default(),
        msg
    );
    let mut s = shared.state.lock().unwrap();
    s.log.push_back(line);
    while s.log.len() > LOG_MAX {
        s.log.pop_front();
    }
}
