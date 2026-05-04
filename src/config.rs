//! Application configuration.
//!
//! This module provides:
//! - [`Config`] — all external configuration parameters

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};

use crate::bpf::{BPFProgram, BaseProfile, Event};

use anyhow::Result;

/// External configuration parameters for netlogger-rs.
pub struct Config {
    /// Maximum number of events transferred per single [`EventBridge::get_events`] call.
    pub max_events_block_size: usize,

    /// Maximum number of events retained in the [`ApplicationContext`] queue.
    pub max_events_log_size: usize,

    /// PID of the root process to monitor.
    pub target_pid: u32,
    /// Default base profile applied when no profile file is loaded.
    pub base_profile: BaseProfile,
    /// Receiver end of the channel for raw BPF events.
    pub event_rx: mpsc::Receiver<Event>,
    /// Shared flag controlling graceful shutdown of background threads.
    pub running_flag: Arc<AtomicBool>,
    /// Reference to the initialized BPF program.
    pub bpf_program: Arc<BPFProgram>,
    /// Optional path to a profile file loaded at startup.
    pub profile_path: Option<String>,
}

/// Builder for constructing a [`Config`] with a fluent API.
///
/// Instantiates the BPF program and event channel during [`ConfigBuilder::build`].
pub struct ConfigBuilder {
    base_profile_value: BaseProfile,
    max_events_block_size_value: usize,
    max_events_log_size_value: usize,
    target_pid_value: u32,
    profile_path_value: Option<String>,
}

impl ConfigBuilder {
    /// Creates a new [`ConfigBuilder`] with default values.
    ///
    /// Defaults: `DenyAll` base profile, no PID target, unlimited event queue.
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            base_profile_value: BaseProfile::DenyAll,
            max_events_block_size_value: 0,
            max_events_log_size_value: 0,
            target_pid_value: 0,
            profile_path_value: None,
        }
    }

    /// Sets the maximum number of events transferred per BPF poll cycle (0 = unlimited).
    pub fn max_events_block_size(mut self, value: usize) -> Self {
        self.max_events_block_size_value = value;
        self
    }

    /// Sets the maximum number of events retained in the in-memory log (0 = unlimited).
    pub fn max_events_log_size(mut self, value: usize) -> Self {
        self.max_events_log_size_value = value;
        self
    }

    /// Sets the PID of the root process whose connections are monitored.
    pub fn target_pid(mut self, value: u32) -> Self {
        self.target_pid_value = value;
        self
    }

    /// Sets the base profile (deny-all or pass-all) applied before any IP list is loaded.
    pub fn base_profile(mut self, value: BaseProfile) -> Self {
        self.base_profile_value = value;
        self
    }

    /// Sets the path to a profile file to load at startup.
    pub fn profile_path(mut self, profile: String) -> Self {
        self.profile_path_value = Some(profile);
        self
    }

    /// Builds the final [`Config`], initializing the BPF program and event channel.
    ///
    /// # Errors
    /// Returns an error if the BPF program fails to load or attach.
    pub fn build(self) -> Result<Config> {
        let running_flag = Arc::new(AtomicBool::new(true));
        let (event_tx, event_rx) = mpsc::channel::<Event>();
        let bpf_program = Arc::new(BPFProgram::new(
            self.target_pid_value,
            self.base_profile_value,
            event_tx,
        )?);
        tracing::info!("[Config] Successfully built");
        Ok(Config {
            max_events_block_size: self.max_events_block_size_value,
            max_events_log_size: self.max_events_log_size_value,
            target_pid: self.target_pid_value,
            event_rx,
            running_flag,
            bpf_program,
            base_profile: self.base_profile_value,
            profile_path: self.profile_path_value,
        })
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
