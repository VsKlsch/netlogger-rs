//! Userspace of BPF Layer of netlogger-rs
//!
//! This module provides:
//! - [`AddressFamily`] - public enum for event's request net family
//! - [`Event`] - structure contains information about connection event
//! - [`BlockEvent`] - structure contains information about block event
//! - [`BPFWorker`] - main structure for BPF layer

mod program_skel;

use std::fmt::Display;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::JoinHandle;
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};

use anyhow::Result;

#[path = "bpf/program_skel.rs"]
#[allow(warnings)]
mod netlogger_ebpf;

use netlogger_ebpf::*;

// SAFETY: The type is #[repr(C)] and contains only those types that cannot have invalid values.
// Thus, it satisfies the requirements of Plain
unsafe impl plain::Plain for netlogger_ebpf::types::event {}

/// Network address family of a connection event.
#[derive(Debug, Clone)]
pub enum AddressFamily {
    /// IPv4 Address family
    Inet,

    /// IPv6 Address family
    Inet6,

    /// Unknown or unsupported family
    Other(u16),
}

impl Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::Inet => write!(f, "AF_INET"),
            AddressFamily::Inet6 => write!(f, "AF_INET6"),
            AddressFamily::Other(_) => write!(f, "UNKNOWN"),
        }
    }
}

impl From<u16> for AddressFamily {
    fn from(v: u16) -> Self {
        match v {
            2 => Self::Inet,
            10 => Self::Inet6,
            v => Self::Other(v),
        }
    }
}

/// Represents a network connection event captured from the BPF layer.
///
/// Contains process information and destination address details.
/// Block/pass state is not included — planned for a future release.
#[derive(Debug, Clone)]
pub struct Event {
    /// Destination IP address of the connection.
    pub ip: IpAddr,

    /// Kernel thread ID (TID). Identifies a specific thread.
    pub pid: u32,

    /// Kernel thread group ID (TGID). Equivalent to userspace PID.
    pub tgid: u32,

    /// Syscall identifier. Currently always 1, reserved for future use.
    pub syscall_id: u32,

    /// Network address family.
    pub family: AddressFamily,

    /// Destination port of the connection.
    pub port: u16,
    /// Event timestamp in nanoseconds since boot (CLOCK_BOOTTIME)
    pub timestamp: u64,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] From: {}:{} [{}:{}] syscall: {} family: {}",
            self.timestamp, self.ip, self.port, self.tgid, self.pid, self.syscall_id, self.family
        )
    }
}

/// Command to block or unblock an IP address in the BPF layer.
#[derive(Debug, Clone)]
pub enum BlockEvent {
    /// Block all new connections to the given IP address.
    Block(IpAddr),

    /// Remove the block for the given IP address.
    Unblock(IpAddr),
}

/// Manages the BPF program lifecycle and event transfer between the kernel and userspace.
///
/// Loads and attaches eBPF programs to tracepoints and cgroups,
/// polls the ring buffer for connection events, and forwards
/// block/unblock commands to the BPF layer.
pub struct BPFWorker {
    worker_handle: Option<JoinHandle<()>>,
    is_running: Arc<AtomicBool>,
}

impl BPFWorker {
    /// Creates BPF Worker and start polling thread
    ///
    /// # Arguments
    /// * target_pid - root pid for logging
    /// * trace_event_sender - sender for EBPF Events
    /// * block_event_receiver - receiver for Block Events
    /// * is_running - shared flag for graceful shutdown
    ///
    /// # Errors
    /// Set is_running flag to false
    pub fn new(
        target_pid: u32,
        trace_event_sender: mpsc::Sender<Event>,
        block_event_receiever: mpsc::Receiver<BlockEvent>,
        is_running: Arc<AtomicBool>,
    ) -> BPFWorker {
        let worker_is_running = is_running.clone();
        BPFWorker {
            worker_handle: Some(std::thread::spawn(move || {
                let local_is_running = worker_is_running.clone();
                match BPFWorker::worker_func(
                    target_pid,
                    trace_event_sender,
                    block_event_receiever,
                    worker_is_running,
                ) {
                    Ok(_) => {}
                    Err(err) => {
                        tracing::error!("Error in BPF Worker: {:?}", err);
                        local_is_running.store(false, Ordering::Relaxed);
                    }
                }
            })),
            is_running,
        }
    }

    fn parse_raw_event(raw_event: netlogger_ebpf::types::event) -> Event {
        let family = AddressFamily::from(raw_event.family);
        let ip = match &family {
            AddressFamily::Inet => {
                let bytes_conversion_result: Result<[u8; 4], _> = raw_event.ip[12..16].try_into();
                match bytes_conversion_result {
                    Ok(bytes) => IpAddr::from(bytes),
                    Err(e) => {
                        tracing::error!("Error when convert slice to bytes array: {:?}", e);
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    }
                }
            }
            AddressFamily::Inet6 => IpAddr::from(raw_event.ip),
            AddressFamily::Other(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };

        Event {
            ip,
            pid: raw_event.pid,
            tgid: raw_event.tgid,
            syscall_id: raw_event.syscall_id,
            family,
            port: raw_event.port,
            timestamp: raw_event.timestamp,
        }
    }

    fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
        let mut raw_ip_addr = [0; 16];
        match ip {
            IpAddr::V4(ipv4_addr) => {
                raw_ip_addr[10] = 0xff;
                raw_ip_addr[11] = 0xff;
                raw_ip_addr[12..16].copy_from_slice(&ipv4_addr.octets()[..]);
            }
            IpAddr::V6(ipv6_addr) => {
                raw_ip_addr[..].copy_from_slice(&ipv6_addr.octets()[..]);
            }
        }
        raw_ip_addr
    }

    fn worker_func(
        target_pid: u32,
        trace_event_sender: mpsc::Sender<Event>,
        block_event_receiever: mpsc::Receiver<BlockEvent>,
        is_running: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut program_skel_builder = ProgramSkelBuilder::default();

        #[cfg(debug_assertions)]
        program_skel_builder.obj_builder.debug(true);

        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = program_skel_builder.open(&mut open_object)?;

        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .expect("rodata is not memory mapped");

        rodata.initial_target_tgid = target_pid;

        let mut skel = open_skel.load()?;

        // SAFETY: The `skel` object has an effective lifetime of `open_object`,
        // but we change it to `static` so that they can coexist in the same structure.
        // Rust's reference mechanism ensures that `skel` will be destroyed before `_open_object`.
        skel.attach()?;

        let cgroup = std::fs::File::open("/sys/fs/cgroup")?;

        let _link_con4 = skel
            .progs
            .connect4_filter
            .attach_cgroup(cgroup.as_raw_fd())?;

        let _link_con6 = skel
            .progs
            .connect6_filter
            .attach_cgroup(cgroup.as_raw_fd())?;

        let mut ringbuffer_builder = RingBufferBuilder::new();
        ringbuffer_builder.add(&skel.maps.events, move |data: &[u8]| {
            let mut raw_event = netlogger_ebpf::types::event::default();
            match plain::copy_from_bytes(&mut raw_event, data) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Error when read package from ringbuffer {:?}", e);
                    return 0;
                }
            };
            let event = BPFWorker::parse_raw_event(raw_event);
            match trace_event_sender.send(event) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Error when send package to Sender {:?}", e);
                    return 0;
                }
            }
            0
        })?;
        let ringbuffer = ringbuffer_builder.build()?;
        let blocked_ips_map = &skel.maps.blocked_ips;
        tracing::info!("BPF Worker is created");

        while is_running.load(Ordering::Relaxed) {
            ringbuffer.poll(Duration::from_millis(100))?;
            if let Ok(block_event) = block_event_receiever.try_recv() {
                match block_event {
                    BlockEvent::Block(ip_addr) => {
                        let raw_addr = BPFWorker::ip_to_bytes(ip_addr);
                        match blocked_ips_map.update(&raw_addr, &[1u8], MapFlags::empty()) {
                            Ok(_) => {
                                tracing::info!("Addr {} blocked", ip_addr);
                            }
                            Err(err) => {
                                tracing::error!("Error when try to block {}: {:?}", ip_addr, err);
                            }
                        }
                    }
                    BlockEvent::Unblock(ip_addr) => {
                        let raw_addr = BPFWorker::ip_to_bytes(ip_addr);
                        match blocked_ips_map.delete(&raw_addr) {
                            Ok(_) => {
                                tracing::info!("Addr {} unblocked", ip_addr);
                            }
                            Err(err) => {
                                tracing::error!("Error when try to unblock {}: {:?}", ip_addr, err);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Drop for BPFWorker {
    fn drop(&mut self) {
        tracing::info!("Drop BPF Worker");
        self.is_running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.worker_handle.take() {
            match handle.join() {
                Ok(_) => {}
                Err(err) => {
                    tracing::error!("Error when stop BPFWorker : {:?}", err);
                }
            }
        }
    }
}
