//! netlogger-rs — eBPF-based network connection monitoring and filtering tool.
//!
//! This crate provides:
//! - [`app`] — application logic, event processing and metrics
//! - [`bpf`] — BPF userspace layer, event capture and IP blocking
//! - [`config`] — application configuration
//!
pub mod app;
pub mod bpf;
pub mod config;
pub mod profile;
