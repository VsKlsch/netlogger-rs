use netlogger_rs::bpf::{BaseProfile, EventStatus};
use netlogger_rs::config::Config;
use netlogger_rs::profile::JsonProfileConverter;
use netlogger_rs::{app::*, config::ConfigBuilder};

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    target_pid: u32,

    #[arg(short, long, required = false)]
    profile_path: Option<String>,
}

struct App {
    app_context: ApplicationContext<JsonProfileConverter>,
    bpf_worker: Option<JoinHandle<Result<()>>>,
    running_flag: Arc<AtomicBool>,
    current_event_sort_field: SortEventField,
    current_event_sort_order: SortOrder,
    current_metric_sort_field: SortMetricField,
    current_metric_sort_order: SortOrder,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, config: Config) -> Result<App> {
        let converter = JsonProfileConverter::default();
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let running_flag = config.running_flag.clone();
        let bpf_worker_running_flag = config.running_flag.clone();
        let bpf_worker_bpf_program = config.bpf_program.clone();

        let bpf_worker = std::thread::spawn(move || -> Result<()> {
            let ringbuffer_res = bpf_worker_bpf_program.build_ringbuffer();
            match ringbuffer_res {
                Ok(ringbuffer) => {
                    while bpf_worker_running_flag.load(Ordering::Relaxed) {
                        match ringbuffer.poll(Duration::from_millis(200)) {
                            Ok(_) => {}
                            Err(err) => {
                                tracing::error!("[BPF Polling Thread]: {:?}", err);
                                bpf_worker_running_flag.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("[BPF Polling Thread]: {:?}", err);
                    bpf_worker_running_flag.store(false, Ordering::Relaxed);
                }
            }
            Ok(())
        });
        let mut app_context = ApplicationContext::new(converter, config)?;

        let current_event_sort_field = SortEventField::Timestamp;
        let current_metric_sort_field = SortMetricField::Count;
        let current_event_sort_order = SortOrder::Ascending;
        let current_metric_sort_order = SortOrder::Descending;

        app_context.set_event_sort_field(current_event_sort_field);
        app_context.set_metric_sort_field(current_metric_sort_field);
        Ok(App {
            app_context,
            bpf_worker: Some(bpf_worker),
            running_flag,
            current_event_sort_field,
            current_event_sort_order,
            current_metric_sort_field,
            current_metric_sort_order,
        })
    }

    fn connections_panel_button(&mut self, ui: &mut egui::Ui, field: SortEventField) {
        let button_name: &str = match field {
            SortEventField::Ip => "Address",
            SortEventField::Pid => "PID",
            SortEventField::Tgid => "TGID",
            SortEventField::Port => "Port",
            SortEventField::Timestamp => "Time",
            SortEventField::L4Protocol => "L4 Protocol",
        };
        if self.current_event_sort_field == field {
            if ui.button(button_name).highlight().clicked() {
                self.current_event_sort_order = match self.current_event_sort_order {
                    SortOrder::Ascending => SortOrder::Descending,
                    SortOrder::Descending => SortOrder::Ascending,
                }
            }
        } else {
            if ui.button(button_name).clicked() {
                self.current_event_sort_field = field;
                self.current_event_sort_order = SortOrder::Ascending;
                self.app_context.set_event_sort_field(field);
            }
        }
    }

    fn ip_metrics_panel_button(&mut self, ui: &mut egui::Ui, field: SortMetricField) {
        let button_name: &str = match field {
            SortMetricField::Ip => "Address",
            SortMetricField::Count => "Count",
        };

        if self.current_metric_sort_field == field {
            if ui.button(button_name).highlight().clicked() {
                self.current_metric_sort_order = match self.current_metric_sort_order {
                    SortOrder::Ascending => SortOrder::Descending,
                    SortOrder::Descending => SortOrder::Ascending,
                }
            }
        } else {
            if ui.button(button_name).clicked() {
                self.current_metric_sort_field = field;
                self.current_metric_sort_order = SortOrder::Ascending;
                self.app_context.set_metric_sort_field(field);
            }
        }
    }

    fn connections_panel(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame, width: f32) {
        let max_events_log_size = self.app_context.get_max_events_log_size();
        // левая панель — список соединений
        egui::Panel::left("connections_panel")
            .exact_size(width)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.set_clip_rect(ui.max_rect());
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Connections");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(format!("{} max", max_events_log_size));
                        });
                    });
                    ui.separator();
                    ui.scope(|ui| {
                        ui.visuals_mut().selection.bg_fill =
                            egui::Color32::from_rgba_unmultiplied(255, 50, 50, 40);
                        TableBuilder::new(ui)
                            .striped(true)
                            .resizable(false)
                            .column(Column::exact(50.0)) // PID
                            .column(Column::exact(50.0)) // TGID
                            .column(Column::exact(100.0)) // L4 Protocol
                            .column(Column::remainder()) // IP — занимает остаток
                            .column(Column::exact(60.0)) // Port
                            .column(Column::exact(130.0)) // Timestamp
                            .header(20.0, |mut header| {
                                header.col(|ui| {
                                    self.connections_panel_button(ui, SortEventField::Pid);
                                });
                                header.col(|ui| {
                                    self.connections_panel_button(ui, SortEventField::Tgid);
                                });
                                header.col(|ui| {
                                    self.connections_panel_button(ui, SortEventField::L4Protocol);
                                });
                                header.col(|ui| {
                                    self.connections_panel_button(ui, SortEventField::Ip);
                                });
                                header.col(|ui| {
                                    self.connections_panel_button(ui, SortEventField::Port);
                                });
                                header.col(|ui| {
                                    self.connections_panel_button(ui, SortEventField::Timestamp);
                                });
                            })
                            .body(|body| {
                                let events: Vec<&DisplayEvent> = self
                                    .app_context
                                    .get_sorted_events_list()
                                    .iter(self.current_event_sort_order)
                                    .collect();
                                body.rows(18.0, events.len(), |mut row| {
                                    let event = &events[row.index()];
                                    if event.raw_event.event_status == EventStatus::Block {
                                        row.set_selected(true);
                                    }
                                    row.col(|ui| {
                                        //ui.visuals_mut().selection.bg_fill = egui::Color32::from_rgba_unmultiplied(255, 50, 50, 40);
                                        ui.monospace(&event.pid);
                                    });
                                    row.col(|ui| {
                                        ui.monospace(&event.tgid);
                                    });
                                    row.col(|ui| {
                                        ui.monospace(&event.l4_protocol);
                                    });
                                    row.col(|ui| {
                                        ui.monospace(&event.ip);
                                    });
                                    row.col(|ui| {
                                        ui.monospace(&event.port);
                                    });
                                    row.col(|ui| {
                                        ui.label(&event.timestamp);
                                    });
                                });
                            });
                    });
                });
            });
    }

    fn summary_panel(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame, height: f32) {
        let mut mode = self.app_context.get_current_base_profile();
        let metrics = self.app_context.get_metrics();
        // правая нижняя — summary
        egui::Panel::bottom("summary_panel")
            .exact_size(height)
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Excludes list");
                    ui.label("Mode:");
                    ui.selectable_value(&mut mode, BaseProfile::PassAll, "Pass All");
                    ui.selectable_value(&mut mode, BaseProfile::DenyAll, "Deny All");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Export profile").clicked() {
                            self.app_context.export_profile();
                        }
                    });
                });
                ui.separator();
                ui.label("Summary");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label("Total connections");
                        ui.heading(metrics.get_total_events().to_string());
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        ui.label("Unique addresses");
                        ui.heading(metrics.get_unique_ip_count().to_string());
                    });
                });
            });
        if mode != self.app_context.get_current_base_profile() {
            self.app_context.set_current_base_profile(mode);
        }
    }

    fn address_statisstics_panel(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // правая верхняя — статистика адресов
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.label("Address statistics");
            ui.separator();
            TableBuilder::new(ui)
                .striped(true)
                .resizable(false)
                .column(Column::remainder()) // PID
                .column(Column::exact(80.0))
                .column(Column::exact(120.0))
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        self.ip_metrics_panel_button(ui, SortMetricField::Ip);
                    });
                    header.col(|ui| {
                        self.ip_metrics_panel_button(ui, SortMetricField::Count);
                    });
                    header.col(|ui| {
                        ui.label("Action");
                    });
                })
                .body(|body| {
                    let metrics = self.app_context.get_metrics();
                    let ip_metrics: Vec<DisplayMetric> = metrics
                        .get_sorted_ip_metrics(self.app_context.get_metric_sort_field())
                        .iter(self.current_metric_sort_order)
                        .collect();
                    body.rows(18.0, metrics.get_unique_ip_count(), |mut row| {
                        let metric = &ip_metrics[row.index()];
                        row.col(|ui| {
                            ui.monospace(&*metric.address);
                        });
                        row.col(|ui| {
                            ui.monospace(&metric.events_count);
                        });
                        row.col(|ui| {
                            if self.app_context.is_in_profile(&metric.ip_addr) {
                                if ui.button("Remove from list").clicked() {
                                    self.app_context.remove_from_profile(metric.ip_addr);
                                }
                            } else {
                                if ui.button("Add to list").clicked() {
                                    self.app_context.add_to_profile(metric.ip_addr);
                                }
                            }
                        });
                    });
                });
        });
    }
}

impl eframe::App for App {
    fn on_exit(&mut self) {
        self.running_flag.store(false, Ordering::Relaxed);
        if let Some(handle) = self.bpf_worker.take() {
            let _ = handle.join();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let available = ctx.content_rect();
        let left_width = available.width() * 0.6;
        let right_height_bottom = available.height() * 0.25;

        if !self.running_flag.load(Ordering::Relaxed) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.connections_panel(ui, frame, left_width);
        self.summary_panel(ui, frame, right_height_bottom);
        self.address_statisstics_panel(ui, frame);
        ctx.request_repaint_after(Duration::from_millis(200));
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let args = Args::parse();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 720.0])
            .with_title(format!("netlogger-rs v{}", env!("CARGO_PKG_VERSION")))
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    let mut app_config_builder = ConfigBuilder::new()
        .base_profile(netlogger_rs::bpf::BaseProfile::DenyAll)
        .max_events_block_size(1000)
        .max_events_log_size(100000)
        .target_pid(args.target_pid);

    if let Some(profile_path) = args.profile_path {
        app_config_builder = app_config_builder.profile_path(profile_path);
    }

    let app_config = app_config_builder.build()?;

    eframe::run_native(
        "netlogger-rs",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc, app_config)?))),
    )?;
    Ok(())
}
