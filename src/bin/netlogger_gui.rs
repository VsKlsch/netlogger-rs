use netlogger_rs::app::*;
use netlogger_rs::bpf::BPFWorker;
use netlogger_rs::config::Config;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

use anyhow::Result;
use clap::Parser;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    target_pid: u32,
}

struct App {
    app_context: ApplicationContext,
    _bpf_worker: BPFWorker,
    _config: Config,
    running_flag: Arc<AtomicBool>,
    current_event_sort_field: SortEventField,
    current_event_sort_order: SortOrder,
    current_metric_sort_field: SortMetricField,
    current_metric_sort_order: SortOrder,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, config: Config) -> Result<App> {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let running_flag = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel();
        let (block_tx, block_rx) = mpsc::channel();
        let bpf_worker = BPFWorker::new(config.target_pid, tx, block_rx, running_flag.clone());
        let mut app_context = ApplicationContext::new(&config, rx, block_tx, running_flag.clone())?;

        let current_event_sort_field = SortEventField::Timestamp;
        let current_metric_sort_field = SortMetricField::Count;
        let current_event_sort_order = SortOrder::Ascending;
        let current_metric_sort_order = SortOrder::Descending;

        app_context.set_event_sort_field(current_event_sort_field);
        app_context.set_metric_sort_field(current_metric_sort_field);
        Ok(App {
            app_context,
            _bpf_worker: bpf_worker,
            _config: config,
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
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(false)
                        .column(Column::exact(50.0)) // PID
                        .column(Column::exact(50.0)) // TGID
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
                                row.col(|ui| {
                                    ui.monospace(&event.pid);
                                });
                                row.col(|ui| {
                                    ui.monospace(&event.tgid);
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
                        })
                });
            });
    }

    fn summary_panel(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame, height: f32) {
        let metrics = self.app_context.get_metrics();
        // правая нижняя — summary
        egui::Panel::bottom("summary_panel")
            .exact_size(height)
            .show_inside(ui, |ui| {
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
                .column(Column::exact(80.0))
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
                            if self.app_context.is_blocked(&metric.ip_addr) {
                                if ui.button("Unblock").clicked() {
                                    self.app_context.unblock(metric.ip_addr);
                                }
                            } else {
                                if ui.button("Block").clicked() {
                                    self.app_context.block(metric.ip_addr);
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

    let app_config = Config {
        max_events_log_size: 100000,
        max_events_block_size: 1000,
        target_pid: args.target_pid,
    };

    eframe::run_native(
        "netlogger-rs",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc, app_config)?))),
    )?;
    Ok(())
}
