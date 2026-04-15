//! Core application logic for netlogger-rs.
//!
//! This module provides:
//! - [`ApplicationContext`] — single point of interaction with the application logic
//! - [`DisplayEvent`] — display representation of a network connection event
//! - [`DisplayMetric`] — display representation of an address metric
//! - [`EventView`] — sorted view over collected events
//! - [`SortEventField`] — sort field selector for events
//! - [`SortMetricField`] — sort field selector for metrics
//! - [`SortOrder`] — sort order (ascending or descending)

mod block_control;
mod event;
mod metric;
mod sort_types;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::{Arc, atomic::AtomicBool};

use crate::app::metric::Metrics;
use crate::bpf::{BlockEvent, Event};
use crate::config::Config;

use block_control::BlockControl;
use event::EventBridge;

pub use event::display_event::DisplayEvent;
pub use event::event_view::EventView;
pub use metric::display_metric::DisplayMetric;
pub use sort_types::{SortEventField, SortMetricField, SortOrder};

use anyhow::Result;

/// Primary entry point for interacting with all application business logic.
///
/// Manages event collection, address metrics, and IP blocking.
/// Acts as a facade over the BPF communication layer, event storage,
/// and blocking control.
#[derive(Debug)]
pub struct ApplicationContext {
    // Configuration
    max_events_log_size: usize,
    start_time: Option<u64>,

    // Components
    event_bridge: EventBridge,
    block_control: BlockControl,

    // Data
    events: VecDeque<DisplayEvent>,
    metrics: Metrics,

    // Fields for generated views
    sort_event_field: SortEventField,
    sort_metric_field: SortMetricField,
}

impl ApplicationContext {
    /// Creates a new `ApplicationContext`.
    ///
    /// Initializes inner components including [`EventBridge`] and [`BlockControl`].
    ///
    /// # Arguments
    /// * `config` — application configuration
    /// * `event_rx` — receiver for BPF events
    /// * `block_event_tx` — sender for block/unblock commands
    /// * `is_running` — shared flag for graceful shutdown
    ///
    /// # Errors
    /// Returns `Err` if any inner component fails to initialize.
    pub fn new(
        config: &Config,
        event_rx: mpsc::Receiver<Event>,
        block_event_sx: mpsc::Sender<BlockEvent>,
        is_running: Arc<AtomicBool>,
    ) -> Result<ApplicationContext> {
        let max_events_log_size = config.max_events_log_size;
        let mut max_events_block_size = config.max_events_block_size;

        if max_events_block_size == 0 && max_events_log_size != 0 {
            max_events_block_size = max_events_log_size;
            tracing::warn!(
                "max_events_log_size != 0 && max_events_block_size == 0. max_events_block_size has been reduced to max_events_log_size"
            );
        }

        if max_events_log_size > 0 && max_events_block_size > max_events_log_size {
            tracing::warn!(
                "max_events_block_size > max_events_log_size. max_events_block_size has been reduced to max_events_log_size"
            );
            max_events_block_size = max_events_log_size;
        }

        let event_bridge = EventBridge::new(max_events_block_size, event_rx, is_running.clone())?;

        tracing::info!("Application context is created");

        Ok(ApplicationContext {
            event_bridge,
            events: VecDeque::new(),
            sort_event_field: SortEventField::Timestamp,
            max_events_log_size,
            metrics: Metrics::new(),
            start_time: None,
            sort_metric_field: SortMetricField::Ip,
            block_control: BlockControl::new(block_event_sx),
        })
    }

    pub fn get_event_sort_field(&self) -> SortEventField {
        self.sort_event_field
    }

    pub fn set_event_sort_field(&mut self, sort_field: SortEventField) {
        self.sort_event_field = sort_field;
    }

    pub fn get_metric_sort_field(&self) -> SortMetricField {
        self.sort_metric_field
    }

    pub fn set_metric_sort_field(&mut self, sort_field: SortMetricField) {
        self.sort_metric_field = sort_field;
    }

    /// Returns a sorted view over the current event queue.
    ///
    /// Retrieves new events from the BPF layer and appends them to the internal
    /// queue, respecting the maximum log size from the configuration.
    ///
    /// # Returns
    /// [`EventView`] with lifetime tied to this [`ApplicationContext`].
    pub fn get_sorted_events_list(&mut self) -> EventView<'_> {
        if let Some(new_events) = self.event_bridge.get_events() {
            if new_events.len() == self.max_events_log_size {
                self.events.clear();
            } else {
                let events_cnt = new_events.len() + self.events.len();
                if self.max_events_log_size > 0 && events_cnt > self.max_events_log_size {
                    let remove_cnt = events_cnt - self.max_events_log_size;
                    self.events.drain(..remove_cnt);
                }
            }
            for event in new_events {
                if self.start_time.is_none() {
                    self.start_time = Some(event.timestamp);
                }

                let mut display_event = DisplayEvent::from(Arc::new(event));
                self.metrics.register_event(&display_event);

                let timestamp_diff_secs: f64 = (display_event.raw_event.timestamp
                    - self.start_time.unwrap_or(display_event.raw_event.timestamp))
                    as f64
                    / 1_000_000.0;

                display_event.timestamp = std::format!("{:.3} ms", timestamp_diff_secs);
                self.events.push_back(display_event);
            }
        }

        EventView::new(&self.events, self.sort_event_field)
    }

    /// Clears the internal event queue.
    ///
    /// Use this after displaying events in CLI mode to free memory.
    pub fn clear_events_list(&mut self) {
        self.events.clear();
    }

    pub fn get_metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn get_max_events_log_size(&self) -> usize {
        self.max_events_log_size
    }

    pub fn block(&mut self, ip: IpAddr) {
        self.block_control.block(ip);
    }

    /// Sends a block command for the given IP address to the BPF layer.
    ///
    /// # Arguments
    /// * `ip` — IP address to block
    pub fn unblock(&mut self, ip: IpAddr) {
        self.block_control.unblock(ip);
    }

    /// Sends a unblock command for the given IP address to the BPF layer.
    ///
    /// # Arguments
    /// * `ip` — IP address to unblock
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.block_control.is_blocked(ip)
    }
}
