//! Application configuration.
//!
//! This module provides:
//! - [`Config`] — all external configuration parameters

/// External configuration parameters for netlogger-rs.
pub struct Config {
    /// Maximum number of events transferred per single [`EventBridge::get_events`] call.
    pub max_events_block_size: usize,

    /// Maximum number of events retained in the [`ApplicationContext`] queue.
    pub max_events_log_size: usize,

    /// PID of the root process to monitor.
    pub target_pid: u32,
}
