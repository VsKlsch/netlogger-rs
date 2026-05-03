//! Sorted view over a sequence of address specific metrics.
//!
//! This module provides [`MetricView`] — a lazily sorted view over
//! a collection of address specific metrics, used for UI table rendering.

use std::net::IpAddr;
use std::sync::Arc;

use std::collections::HashMap;

use crate::app::{SortMetricField, SortOrder, metric::display_metric::DisplayMetric};

/// Lazily sorted view over a collection of address specific metrics, used for UI table rendering.
#[derive(Debug)]
pub struct MetricView<'a> {
    metrics: &'a HashMap<IpAddr, usize>,
    addr_strings: &'a HashMap<IpAddr, Arc<str>>,
    sort_by: SortMetricField,
}

impl<'a> MetricView<'a> {
    /// Creates a [`MetricView`] with metrics from HashMap and sorted by SortMetricField
    ///
    /// # Arguments
    /// * metrics - reference to a [`HashMap`] with keys of type [`IpAddr`] and values of type usize
    /// * addr_strings - reference to a [`HashMap`] with keys of type [`IpAddr`] and values of type [`Arc`] to [`str`]
    /// * sort_by - selector field for sorting
    ///
    /// # Returns
    /// [`MetricView`] with lifetime tied to events VecDeque
    pub fn new(
        metrics: &'a HashMap<IpAddr, usize>,
        addr_strings: &'a HashMap<IpAddr, Arc<str>>,
        sort_by: SortMetricField,
    ) -> MetricView<'a> {
        MetricView {
            metrics,
            addr_strings,
            sort_by,
        }
    }

    /// Returns an iterator over address metrics sorted by the configured field and given order.
    ///
    /// Collects metrics into a temporary buffer, sorts them, and returns
    /// an iterator of owned [`DisplayMetric`] values ready for UI rendering.
    ///
    /// # Arguments
    /// * `sort_type` — sort order (ascending or descending)
    ///
    /// # Returns
    /// Iterator over owned [`DisplayMetric`] values sorted by [`SortMetricField`].
    pub fn iter(&self, sort_type: SortOrder) -> impl Iterator<Item = DisplayMetric> {
        let mut vec: Vec<(&'_ IpAddr, &'_ usize)> = self.metrics.iter().collect();

        vec.sort_by(|a, b| {
            let ord = match self.sort_by {
                SortMetricField::Ip => a.0.cmp(b.0),
                SortMetricField::Count => a.1.cmp(b.1),
            };
            match sort_type {
                SortOrder::Ascending => ord,
                SortOrder::Descending => ord.reverse(),
            }
        });
        vec.into_iter().map(|metric| DisplayMetric {
            address: self
                .addr_strings
                .get(metric.0)
                .cloned()
                .unwrap_or(Arc::from("address_not_in_storage")),
            events_count: metric.1.to_string(),
            ip_addr: *metric.0,
        })
    }

    /// Returns the number of unique addresses in this metrics view.
    pub fn len(&self) -> usize {
        self.metrics.len()
    }
}
