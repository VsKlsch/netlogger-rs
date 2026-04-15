//! Address and connection metrics.
//!
//! This module provides:
//! - [`Metrics`] — tracks per-address connection counts and total connection statistics
//! - [`display_metric`] — display representation of address metrics
//! - [`metric_view`] — sorted view over collected address metrics

pub mod display_metric;
pub mod metric_view;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::app::{DisplayEvent, SortMetricField, metric::metric_view::MetricView};

/// Address and connection metrics
#[derive(Debug)]
pub struct Metrics {
    ip_events_metric: HashMap<IpAddr, usize>,
    ip_string_storage: HashMap<IpAddr, Arc<str>>,
    total_events: usize,
}

impl Metrics {
    /// Creates empty metrics
    pub fn new() -> Metrics {
        Metrics {
            ip_events_metric: HashMap::new(),
            ip_string_storage: HashMap::new(),
            total_events: 0,
        }
    }

    /// Register new event in metrics
    ///
    /// Increment total metrics and address specific metrics
    pub fn register_event(&mut self, event: &DisplayEvent) {
        match self.ip_events_metric.get_mut(&event.raw_event.ip) {
            Some(value) => *value += 1,
            None => {
                self.ip_events_metric.insert(event.raw_event.ip, 1);
                self.ip_string_storage
                    .insert(event.raw_event.ip, Arc::from(event.ip.clone()));
            }
        }
        self.total_events += 1;
    }

    pub fn get_total_events(&self) -> usize {
        self.total_events
    }

    /// Returns a sorted view over the per-address connection metrics.
    ///
    /// # Arguments
    /// * `field` — field to sort by
    ///
    /// # Returns
    /// [`MetricView`] with lifetime tied to this [`Metrics`].
    pub fn get_sorted_ip_metrics(&self, field: SortMetricField) -> MetricView<'_> {
        MetricView::new(&self.ip_events_metric, &self.ip_string_storage, field)
    }

    pub fn get_unique_ip_count(&self) -> usize {
        self.ip_events_metric.len()
    }
}
