//! Display representation of a network connection event.
//!
//! This module provides [`DisplayEvent`] — a ready-to-render representation
//! of a connection event with pre-formatted string fields for UI display.

use std::fmt::Display;
use std::sync::Arc;

use crate::bpf::Event;

/// Ready-to-render representation of a network connection event.
///
/// Contains pre-formatted string fields for direct use in UI tables,
/// alongside a reference to the original event for sorting and filtering.
#[derive(Debug, Clone)]
pub struct DisplayEvent {
    /// Reference to the original event, used for sorting and filtering.
    pub raw_event: Arc<Event>,
    /// Destination IP address as a formatted string.
    pub ip: String,
    /// Thread ID (kernel pid) as a formatted string.
    pub pid: String,
    /// Process ID (kernel tgid) as a formatted string.
    pub tgid: String,
    /// Destination port as a formatted string.
    pub port: String,
    /// Time elapsed since the first captured event.
    pub timestamp: String,
    /// Network address family as a formatted string.
    pub family: String,
}

impl From<Arc<Event>> for DisplayEvent {
    fn from(e: Arc<Event>) -> DisplayEvent {
        DisplayEvent {
            ip: e.ip.to_string(),
            pid: e.pid.to_string(),
            tgid: e.tgid.to_string(),
            port: e.port.to_string(),
            timestamp: e.timestamp.to_string(),
            family: e.family.to_string(),
            raw_event: e,
        }
    }
}

impl Display for DisplayEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] From: {}:{} [{}:{}] family: {}",
            self.timestamp, self.ip, self.port, self.tgid, self.pid, self.family
        )
    }
}
