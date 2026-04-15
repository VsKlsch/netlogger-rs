use netlogger_rs::app::{ApplicationContext, SortOrder};
use netlogger_rs::bpf;
use netlogger_rs::config::Config;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use anyhow::Result;
use clap::Parser;

use bpf::{BPFWorker, BlockEvent, Event};

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

    let (tx, rx) = mpsc::channel::<Event>();
    let (block_tx, block_rx) = mpsc::channel::<BlockEvent>();
    let config = Config {
        max_events_block_size: 0,
        max_events_log_size: 0,
        target_pid: args.target_pid,
    };
    let _bpf_worker = BPFWorker::new(args.target_pid, tx, block_rx, running_flag.clone());
    let mut app_contex = ApplicationContext::new(&config, rx, block_tx, running_flag.clone())?;

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
