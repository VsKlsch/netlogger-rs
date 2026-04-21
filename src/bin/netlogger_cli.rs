use netlogger_rs::app::{ApplicationContext, SortOrder};
use netlogger_rs::config::ConfigBuilder;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    target_pid: u32,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let running_flag = Arc::new(AtomicBool::new(true));

    let ctrlc_flag_clone = running_flag.clone();

    ctrlc::set_handler(move || {
        ctrlc_flag_clone.store(false, Ordering::Relaxed);
    })?;

    let app_config = ConfigBuilder::new()
        .base_profile(netlogger_rs::bpf::BaseProfile::DenyAll)
        .max_events_block_size(0)
        .max_events_log_size(0)
        .target_pid(args.target_pid)
        .build()?;
    let mut app_contex = ApplicationContext::new(app_config)?;

    while running_flag.load(Ordering::Relaxed) {
        app_contex
            .get_sorted_events_list()
            .iter(SortOrder::Ascending)
            .for_each(|e| println!("{}", e));
        app_contex.clear_events_list();
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
