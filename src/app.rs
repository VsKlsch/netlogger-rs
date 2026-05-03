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

mod event;
mod metric;
mod profile_control;
mod sort_types;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use crate::app::metric::Metrics;
use crate::bpf::BaseProfile;
use crate::config::Config;
use crate::profile::{Profile, ProfileConverter, ProfileV1};

use event::EventBridge;
use profile_control::ProfileControl;

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
pub struct ApplicationContext<Converter: ProfileConverter> {
    // Configuration
    max_events_log_size: usize,
    start_time: Option<u64>,

    // Components
    event_bridge: EventBridge,
    profile_control: ProfileControl,

    // Data
    events: VecDeque<DisplayEvent>,
    metrics: Metrics,

    // Fields for generated views
    sort_event_field: SortEventField,
    sort_metric_field: SortMetricField,

    converter: Converter,
}

impl<C: ProfileConverter> ApplicationContext<C> {
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
    pub fn new(converter: C, config: Config) -> Result<ApplicationContext<C>> {
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

        let event_bridge = EventBridge::new(
            max_events_block_size,
            config.event_rx,
            config.running_flag.clone(),
        )?;

        let mut metrics = Metrics::new();
        let mut profile_control =
            ProfileControl::new(config.bpf_program.clone(), config.base_profile);

        if let Some(profile_path) = config.profile_path {
            let raw_profile = std::fs::read_to_string(profile_path)?;
            let profile = converter.deserialize(&raw_profile)?;

            profile.ip_list.into_iter().for_each(|ip| {
                if profile_control.add(ip).is_ok() {
                    metrics.register_zero_event_ip(ip);
                }
            });

            if profile.base_profile != profile_control.get_current_base_profile() {
                profile_control.set_current_base_profile(profile.base_profile)?;
            }
        }

        tracing::info!("Application context is created");

        Ok(ApplicationContext {
            event_bridge,
            events: VecDeque::new(),
            sort_event_field: SortEventField::Timestamp,
            max_events_log_size,
            metrics,
            start_time: None,
            sort_metric_field: SortMetricField::Ip,
            profile_control,
            converter,
        })
    }

    /// Returns the current sort field for the events table.
    pub fn get_event_sort_field(&self) -> SortEventField {
        self.sort_event_field
    }

    /// Sets the sort field for the events table.
    pub fn set_event_sort_field(&mut self, sort_field: SortEventField) {
        self.sort_event_field = sort_field;
    }

    /// Returns the current sort field for the metrics table.
    pub fn get_metric_sort_field(&self) -> SortMetricField {
        self.sort_metric_field
    }

    /// Sets the sort field for the metrics table.
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
                    / 1_000_000_000.0;

                display_event.timestamp = std::format!("{:.3} s", timestamp_diff_secs);
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

    /// Returns a reference to the address metrics store.
    pub fn get_metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Returns the configured maximum number of events retained in the log.
    pub fn get_max_events_log_size(&self) -> usize {
        self.max_events_log_size
    }

    /// Adds the given IP address to the block/allow list via the BPF layer.
    pub fn add_to_profile(&mut self, ip: IpAddr) {
        let _ = self.profile_control.add(ip);
    }

    /// Removes the given IP address from the block/allow list via the BPF layer.
    ///
    /// # Arguments
    /// * `ip` — IP address to remove
    pub fn remove_from_profile(&mut self, ip: IpAddr) {
        let _ = self.profile_control.remove(ip);
    }

    /// Checks whether the given IP address is present in the block/allow list.
    ///
    /// # Arguments
    /// * `ip` — IP address to check
    pub fn is_in_profile(&self, ip: &IpAddr) -> bool {
        self.profile_control.contains(ip)
    }

    fn collect_profile_from_metrics(&self) -> Profile {
        Profile::from(ProfileV1 {
            base_profile: self.profile_control.get_current_base_profile(),
            ip_list: self.profile_control.dump_profile_addrs(),
        })
    }

    /// Opens a file save dialog and exports the current profile to a file.
    ///
    /// Serialization is delegated to the configured [`ProfileConverter`].
    /// The export runs on a separate thread to avoid blocking the UI.
    pub fn export_profile(&self) {
        let profile = self.collect_profile_from_metrics();
        match self.converter.serialize(&profile) {
            Ok(profile_str) => {
                std::thread::spawn(move || {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name(C::DEFAULT_PROFILE_NAME)
                        .add_filter(C::DEFAULT_PROFILE_NAME, C::PROFILE_EXTENSIONS)
                        .save_file()
                        && let Err(err) = std::fs::write(path, profile_str)
                    {
                        tracing::error!("[ProfileWriterWorker] Error: {:?}", err);
                    }
                });
            }
            Err(err) => {
                tracing::error!("[AppContext] Error: {:?}", err);
            }
        }
    }

    /// Returns the currently active base filtering profile.
    pub fn get_current_base_profile(&self) -> BaseProfile {
        self.profile_control.get_current_base_profile()
    }

    /// Sets the base filtering profile (pass-all or deny-all).
    pub fn set_current_base_profile(&mut self, profile: BaseProfile) {
        let _ = self.profile_control.set_current_base_profile(profile);
    }
}
