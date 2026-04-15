//! Sort field selectors and ordering for UI tables.
//!
//! This module provides:
//! - [`SortEventField`] — sort field selector for the connections table
//! - [`SortMetricField`] — sort field selector for the address statistics table
//! - [`SortOrder`] — sort order (ascending or descending)

/// Sort field selector for connections table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortEventField {
    /// Sort by Destination address.
    Ip,
    /// Sort by Kernel PID.
    Pid,
    /// Sort by Kernel TGID.
    Tgid,
    /// Sort by Destination port.
    Port,
    /// Sort by timestamp.
    Timestamp,
}

/// Sort field selector for metrics table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMetricField {
    /// Sort by Destination address.
    Ip,
    /// Sort by connections count.
    Count,
}

/// Ordering types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Sort from lowest to highest.
    Ascending,
    /// Sort from highest to lowest.
    Descending,
}
