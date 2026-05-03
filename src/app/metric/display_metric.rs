//! Display representation of an address specific metric.
//!
//! This module provides [`DisplayMetric`] — a ready-to-render representation
//! of an address specific metric with pre-formatted string fields for UI display.

use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;

/// Ready-to-render representation of an address
/// specific metric with pre-formatted string fields for UI display.
///
/// Contains pre-formatted string fields for direct use in UI tables
/// and raw ip for block button.
#[derive(Debug, Clone)]
pub struct DisplayMetric {
    /// Destination IP address as a formatted string.
    pub address: Arc<str>,
    /// Count of connection events as a formatted string.
    pub events_count: String,
    /// Destination IP address as a [`IpAddr`]`
    pub ip_addr: IpAddr,
}

impl Display for DisplayMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.address, self.events_count)
    }
}
