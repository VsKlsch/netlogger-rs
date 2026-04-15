//! Sorted view over a sequence of connection events.
//!
//! This module provides [`EventView`] — a lazily sorted view over
//! a collection of connection events, used for UI table rendering.

use std::collections::VecDeque;

use super::display_event::DisplayEvent;
use crate::app::sort_types::{SortEventField, SortOrder};

/// Lazily sorted view over a collection of connection events, used for UI table rendering.
#[derive(Debug)]
pub struct EventView<'a> {
    events: &'a VecDeque<DisplayEvent>,
    sort_by: SortEventField,
}

impl<'a> EventView<'a> {
    /// Creates a [`EventView`] with events from VecDeque and sorted by SortEventField
    ///
    /// # Arguments
    /// * events - reference to a VecDeque of [`DisplayEvent`]
    /// * sort_by - selector field for sorting
    ///
    /// # Returns
    /// [`EventView`] with lifetime tied to events VecDeque
    pub fn new(events: &'a VecDeque<DisplayEvent>, sort_by: SortEventField) -> EventView<'a> {
        EventView { events, sort_by }
    }

    /// Returns an iterator over events sorted by the configured field and given order.
    ///
    /// Collects events into a temporary buffer, sorts them, and returns
    /// an iterator over references with lifetime tied to the source collection.
    ///
    /// # Arguments
    /// * `order` — sort order (ascending or descending)
    ///
    /// # Returns
    /// Iterator over [`DisplayEvent`] references sorted by [`SortEventField`].
    pub fn iter(&self, order: SortOrder) -> impl Iterator<Item = &'a DisplayEvent> {
        let mut vec = self.events.iter().collect::<Vec<&'a DisplayEvent>>();

        vec.sort_by(|a, b| {
            let ord = match self.sort_by {
                SortEventField::Ip => a.raw_event.ip.cmp(&b.raw_event.ip),
                SortEventField::Pid => a.raw_event.pid.cmp(&b.raw_event.pid),
                SortEventField::Tgid => a.raw_event.tgid.cmp(&b.raw_event.tgid),
                SortEventField::Port => a.raw_event.port.cmp(&b.raw_event.port),
                SortEventField::Timestamp => a.raw_event.timestamp.cmp(&b.raw_event.timestamp),
            };
            match order {
                SortOrder::Ascending => ord,
                SortOrder::Descending => ord.reverse(),
            }
        });

        vec.into_iter()
    }

    pub fn len(&self) -> usize {
        self.events.iter().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
