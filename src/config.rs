//! Application configuration.
//!
//! This module provides:
//! - [`Config`] — all external configuration parameters

use std::sync::{mpsc, Arc};
use std::sync::atomic::AtomicBool;

use crate::bpf::{Event, BPFProgram, BaseProfile};

use anyhow::Result;

/// External configuration parameters for netlogger-rs.
pub struct Config {
    /// Maximum number of events transferred per single [`EventBridge::get_events`] call.
    pub max_events_block_size: usize,

    /// Maximum number of events retained in the [`ApplicationContext`] queue.
    pub max_events_log_size: usize,

    /// PID of the root process to monitor.
    pub target_pid: u32,
    pub base_profile: BaseProfile,
    pub event_rx: mpsc::Receiver<Event>,
    pub running_flag: Arc<AtomicBool>,
    pub bpf_program: Arc<BPFProgram>
}

pub struct ConfigBuilder {
    base_profile_value: BaseProfile,
    max_events_block_size_value: usize,
    max_events_log_size_value: usize,
    target_pid_value: u32 
}

impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            base_profile_value: BaseProfile::DenyAll,
            max_events_block_size_value: 0,
            max_events_log_size_value: 0,
            target_pid_value: 0
        }
    }

    pub fn max_events_block_size(mut self, value: usize) -> Self {
        self.max_events_block_size_value = value;
        self
    }

    pub fn max_events_log_size(mut self, value: usize) -> Self {
        self.max_events_log_size_value = value;
        self
    }

    pub fn target_pid(mut self, value: u32) -> Self {
        self.target_pid_value = value;
        self
    }

    pub fn base_profile(mut self, value: BaseProfile) -> Self{
        self.base_profile_value = value;
        self
    }

    pub fn build(self) -> Result<Config> {
        let running_flag = Arc::new(AtomicBool::new(true));
        let (event_tx, event_rx) = mpsc::channel::<Event>();
        let bpf_program = Arc::new(
            BPFProgram::new(
                self.target_pid_value, 
                self.base_profile_value,
                event_tx
            )?
        );
        tracing::info!("[Config] Successfully built");
        Ok(Config{
            max_events_block_size: self.max_events_block_size_value,
            max_events_log_size: self.max_events_log_size_value,
            target_pid: self.target_pid_value,
            event_rx,
            running_flag,
            bpf_program,
            base_profile: self.base_profile_value
        })
    }
}

