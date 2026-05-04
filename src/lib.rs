//! netlogger-rs — eBPF-based network connection monitoring and filtering tool.
//!
//! Connections are captured directly in cgroup hooks (connect/sendmsg)
//! and streamed to userspace via a BPF ring buffer. An IP block/allow list
//! combined with a deny-all or pass-all base profile controls which
//! connections are permitted.
//!
//! This crate provides:
//! - [`app`] — application logic, event buffering, metrics and profile management
//! - [`bpf`] — BPF userspace layer: program loading, event parsing, IP list control
//! - [`config`] — application configuration and BPF program initialisation
//! - [`profile`] — profile serialization/deserialization and format conversion
//!
pub mod app;
pub mod bpf;
pub mod config;
pub mod profile;
