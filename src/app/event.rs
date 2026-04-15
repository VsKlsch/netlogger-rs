//! Event collection and processing pipeline.
//!
//! This module provides:
//! - [`EventBridge`] — receives raw BPF events, buffers them and exposes
//!   a sorted view for the application layer
//! - [`display_event`] — display representation of connection events
//! - [`event_view`] — sorted view over collected events

pub mod display_event;
pub mod event_view;

use std::sync::mpsc;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use crate::bpf::Event;

use anyhow::Result;

/// Bridges the BPF layer and the application by collecting and buffering connection events.
///
/// Runs a background thread that receives raw [`Event`] objects from the BPF layer
/// and stores them in a bounded queue. Events can be retrieved by the application
/// layer via [`EventBridge::get_events`].
///
/// Stops the background thread gracefully on drop.
#[derive(Debug)]
pub struct EventBridge {
    events: Arc<Mutex<VecDeque<Event>>>,
    run_fn_join_handle: Option<JoinHandle<Result<()>>>,
    is_running: Arc<AtomicBool>,
}

impl EventBridge {
    /// Creates a new `EventBridge` and starts the background event collection thread.
    ///
    /// # Arguments
    /// * `max_events` — maximum number of events retained in the internal queue
    /// * `event_receiver` — receiver for raw BPF events
    /// * `is_running` — shared flag for graceful shutdown
    ///
    /// # Errors
    /// Returns `Err` if the background thread fails to start.
    pub fn new(
        max_events: usize,
        event_reciever: mpsc::Receiver<Event>,
        is_running: Arc<AtomicBool>,
    ) -> Result<EventBridge> {
        let events = Arc::new(Mutex::new(VecDeque::with_capacity(max_events)));
        let thread_events = events.clone();
        let thread_is_running = is_running.clone();
        tracing::info!("Event provider created");
        Ok(EventBridge {
            events,
            run_fn_join_handle: Some(std::thread::spawn(move || {
                EventBridge::run(max_events, event_reciever, thread_events, thread_is_running)
            })),
            is_running,
        })
    }

    fn lock_events(events: &Mutex<VecDeque<Event>>) -> MutexGuard<'_, VecDeque<Event>> {
        match events.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Last access to mutex finished with panic");
                poisoned.into_inner()
            }
        }
    }

    fn run(
        max_events: usize,
        event_reciever: mpsc::Receiver<Event>,
        events: Arc<Mutex<VecDeque<Event>>>,
        is_running: Arc<AtomicBool>,
    ) -> Result<()> {
        while is_running.load(Ordering::Relaxed) {
            match event_reciever.try_recv() {
                Ok(event) => {
                    let mut guard = EventBridge::lock_events(&events);
                    if max_events > 0 && guard.len() == max_events {
                        guard.pop_front();
                    }
                    guard.push_back(event);
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
        Ok(())
    }

    /// Drains and returns all buffered events from the internal queue.
    ///
    /// Returns `None` if no events have been collected since the last call.
    ///
    /// # Returns
    /// `Some` with all buffered events, or `None` if the queue is empty.
    pub fn get_events(&self) -> Option<VecDeque<Event>> {
        let mut guard = EventBridge::lock_events(&self.events);
        let out_vec = std::mem::take(&mut *guard);
        if out_vec.is_empty() {
            None
        } else {
            Some(out_vec)
        }
    }
}

impl Drop for EventBridge {
    fn drop(&mut self) {
        tracing::info!("Drop Event Provider");
        self.is_running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.run_fn_join_handle.take()
            && let Err(err) = handle.join()
        {
            tracing::error!("Error in EventBridge thread: {:?}", err);
        }
    }
}
