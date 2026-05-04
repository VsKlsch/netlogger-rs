//! Userspace layer for the netlogger-rs eBPF program.
//!
//! Handles BPF program loading, cgroup attachment, map operations,
//! ring buffer polling, and raw event parsing into typed Rust structures.
//!
//! This module provides:
//! - [`AddressFamily`] — network address family of a connection event
//! - [`L4Protocol`] — transport-layer protocol (TCP/UDP)
//! - [`ParseStatus`] — outcome of address parsing from the BPF context
//! - [`EventStatus`] — whether the connection was blocked or passed
//! - [`BaseProfile`] — deny-all or pass-all base filtering mode
//! - [`Event`] — parsed network connection event
//! - [`IpListEvent`] — command to add or remove an IP from the BPF list
//! - [`BPFProgram`] — loaded and attached eBPF program instance
//! - [`BPFError`] — BPF initialisation errors

mod program_skel;

use std::error::Error;
use std::fmt::Display;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::mpsc;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, OpenObject, RingBuffer, RingBufferBuilder};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[path = "bpf/program_skel.rs"]
#[allow(warnings)]
mod netlogger_ebpf;

use netlogger_ebpf::*;

// SAFETY: The type is #[repr(C)] and contains only those types that cannot have invalid values.
// Thus, it satisfies the requirements of Plain
unsafe impl plain::Plain for netlogger_ebpf::types::event {}

// Key constant for current filter profile mode
const PROFILE_MODE_KEY: [u8; 4] = [0u8; 4];

// IP List value
const IP_LIST_VALUE: [u8; 1] = [1u8];

/// Network address family of a connection event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 Address family
    Inet,

    /// IPv6 Address family
    Inet6,

    /// Unix domain socket family
    Unix,
    /// Unknown or unsupported family
    Other(u16),
}

impl Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::Inet => write!(f, "AF_INET"),
            AddressFamily::Inet6 => write!(f, "AF_INET6"),
            AddressFamily::Other(_) => write!(f, "UNKNOWN"),
            AddressFamily::Unix => write!(f, "AF_UNIX"),
        }
    }
}

impl From<u16> for AddressFamily {
    fn from(v: u16) -> Self {
        match v {
            2 => Self::Inet,
            10 => Self::Inet6,
            16 => Self::Unix,
            v => Self::Other(v),
        }
    }
}

/// Layer 4 (transport) protocol of a connection event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum L4Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
    /// Unknown or unsupported protocol (raw number).
    Other(u8),
}

impl Display for L4Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Other(num) => write!(f, "Other({})", num),
        }
    }
}

impl From<u8> for L4Protocol {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Tcp,
            1 => Self::Udp,
            v => Self::Other(v),
        }
    }
}

/// Outcome of parsing the destination address from the BPF cgroup context.
///
/// Since addresses are read from kernel memory (not userspace),
/// the only possible error is an unrecognized address family.
#[derive(Debug, Clone)]
pub enum ParseStatus {
    /// Address was parsed successfully.
    Success,
    /// Address family was unrecognized (not AF_INET or AF_INET6).
    ErrorUnknownFamily,
    /// Unknown parse status code (reserved for forward compatibility).
    Other(u8),
}

impl Display for ParseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::ErrorUnknownFamily => write!(f, "Error at unknown family"),
            Self::Other(num) => write!(f, "Other({})", num),
        }
    }
}

impl From<u8> for ParseStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::ErrorUnknownFamily,
            v => Self::Other(v),
        }
    }
}

/// Whether a connection event was blocked or passed by the BPF filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStatus {
    /// Status could not be determined.
    Unknown,
    /// Connection was blocked.
    Block,
    /// Connection was allowed to pass.
    Pass,
    /// Unknown or unsupported status (raw code).
    Other(u8),
}

impl Display for EventStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Block => write!(f, "Block"),
            Self::Pass => write!(f, "Pass"),
            Self::Other(num) => write!(f, "Other({})", num),
        }
    }
}

impl From<u8> for EventStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Block,
            1 => Self::Pass,
            2 => Self::Unknown,
            v => Self::Other(v),
        }
    }
}

/// Base filtering profile applied by the BPF program.
///
/// Determines the default behaviour for connections not explicitly listed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BaseProfile {
    /// Deny all connections by default; only explicitly listed IPs are allowed.
    #[default]
    DenyAll,
    /// Allow all connections by default; only explicitly listed IPs are blocked.
    PassAll,
    /// Unknown or unsupported profile mode (raw code).
    Other(u8),
}

impl Display for BaseProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DenyAll => write!(f, "Deny All"),
            Self::PassAll => write!(f, "Pass All"),
            Self::Other(num) => write!(f, "Other({})", num),
        }
    }
}

impl From<u8> for BaseProfile {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::DenyAll,
            1 => Self::PassAll,
            v => Self::Other(v),
        }
    }
}

impl From<BaseProfile> for u8 {
    fn from(val: BaseProfile) -> Self {
        match val {
            BaseProfile::DenyAll => 0u8,
            BaseProfile::PassAll => 1u8,
            BaseProfile::Other(v) => v,
        }
    }
}

/// Represents a network connection event captured from the BPF cgroup hooks.
///
/// Contains process information, destination address, transport protocol,
/// parsing outcome, and the block/pass decision applied by the BPF filter.
#[derive(Debug, Clone)]
pub struct Event {
    /// Destination IP address of the connection.
    pub ip: IpAddr,

    /// Kernel thread ID (TID). Identifies a specific thread.
    pub pid: u32,

    /// Kernel thread group ID (TGID). Equivalent to userspace PID.
    pub tgid: u32,

    /// Network address family.
    pub family: AddressFamily,

    /// Destination port of the connection.
    pub port: u16,

    /// Event timestamp in nanoseconds since boot (CLOCK_BOOTTIME)
    pub timestamp: u64,

    /// Event status may be Block or Pass
    pub event_status: EventStatus,

    /// Outcome of address parsing: success or unknown family error.
    pub parse_status: ParseStatus,

    /// L4 type
    pub l4_protocol: L4Protocol,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] From: {}:{} [{}:{}] family: {}",
            self.timestamp, self.ip, self.port, self.tgid, self.pid, self.family
        )
    }
}

/// Command sent to the BPF layer to add or remove an IP address.
#[derive(Debug, Clone)]
pub enum IpListEvent {
    /// Add the given IP to the BPF IP list map.
    AddToList(IpAddr),

    /// Remove the given IP from the BPF IP list map.
    RemoveFromList(IpAddr),
}

/// Errors that can occur during BPF program initialisation.
#[derive(Debug, Clone, Copy)]
pub enum BPFError {
    /// Failed to retrieve the read-only data section from the BPF skeleton.
    RodataRetrievengError(&'static str),
}

impl Display for BPFError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            BPFError::RodataRetrievengError(err) => {
                write!(f, "Error when create BPFProgram: {}", err)
            }
        }
    }
}

impl Error for BPFError {}

/// Loaded and attached eBPF program controlling network connection filtering.
///
/// Holds the BPF skeleton, cgroup attachment links, and the event sender channel.
/// Created via [`BPFProgram::new`].
pub struct BPFProgram {
    _link_con4: Link,
    _link_con6: Link,
    _link_sendmsg4: Link,
    _link_sendmsg6: Link,
    skel: ProgramSkel<'static>,
    _open_object: Pin<Box<MaybeUninit<OpenObject>>>,
    sender: mpsc::Sender<Event>,
}

impl BPFProgram {
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
            AddressFamily::Other(_) | AddressFamily::Unix => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let event_status = EventStatus::from(raw_event.event_status);
        let parse_status = ParseStatus::from(raw_event.parse_status);
        let l4_protocol = L4Protocol::from(raw_event.l4_protocol);

        Event {
            ip,
            pid: raw_event.pid,
            tgid: raw_event.tgid,
            family,
            port: raw_event.port,
            timestamp: raw_event.timestamp,
            event_status,
            parse_status,
            l4_protocol,
        }
    }

    /// Loads and attaches the eBPF program, configuring it for the given target PID and base profile.
    ///
    /// Attaches cgroup hooks for connect and sendmsg filtering,
    /// plus sched_process_fork/exit tracepoints for process tree tracking.
    ///
    /// # Arguments
    /// * `target_pid` — PID (TGID) of the root process whose connections to monitor
    /// * `base_profile` — initial filtering profile (deny-all or pass-all)
    /// * `trace_event_sender` — sender for connection events captured by the BPF probe
    ///
    /// # Errors
    /// Returns an error if the BPF program fails to load, attach to cgroup hooks,
    /// or attach to tracepoints.
    pub fn new(
        target_pid: u32,
        base_profile: BaseProfile,
        trace_event_sender: mpsc::Sender<Event>,
    ) -> Result<BPFProgram> {
        let mut program_skel_builder = ProgramSkelBuilder::default();

        #[cfg(debug_assertions)]
        program_skel_builder.obj_builder.debug(true);

        let mut open_object = Box::pin(MaybeUninit::uninit());
        let mut open_skel = program_skel_builder.open(&mut open_object)?;
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or(BPFError::RodataRetrievengError("Error retrieveng ROData"))?;

        rodata.fallback_profile = base_profile.into();
        rodata.initial_target_tgid = target_pid;

        let skel = open_skel.load()?;

        // SAFETY: The `skel` object has an effective lifetime of `open_object`,
        // but we change it to `static` so that they can coexist in the same structure BPFProgram.
        // Rust's reference mechanism ensures that `skel` will be destroyed before `_open_object`.
        let mut skel: ProgramSkel<'static> = unsafe { std::mem::transmute(skel) };
        let cp_value: [u8; 1] = [base_profile.into()];
        skel.maps.profile_mode.update(
            &PROFILE_MODE_KEY,
            &cp_value,
            libbpf_rs::MapFlags::empty(),
        )?;

        skel.attach()?;

        tracing::info!("[BPF Program] Cgroup hooks and tracepoints successfully attached");

        let cgroup = std::fs::File::open("/sys/fs/cgroup")?;

        let link_con4 = skel
            .progs
            .connect4_filter
            .attach_cgroup(cgroup.as_raw_fd())?;

        let link_con6 = skel
            .progs
            .connect6_filter
            .attach_cgroup(cgroup.as_raw_fd())?;

        let link_sendmsg4 = skel
            .progs
            .sendmsg4_filter
            .attach_cgroup(cgroup.as_raw_fd())?;

        let link_sendmsg6 = skel
            .progs
            .sendmsg6_filter
            .attach_cgroup(cgroup.as_raw_fd())?;

        Ok(BPFProgram {
            _link_con4: link_con4,
            _link_con6: link_con6,
            _link_sendmsg4: link_sendmsg4,
            _link_sendmsg6: link_sendmsg6,
            _open_object: open_object,
            skel,
            sender: trace_event_sender,
        })
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

    /// Sends an add-to-list or remove-from-list command to the BPF IP list map.
    ///
    /// # Arguments
    /// * `event` — [`IpListEvent`] specifying the IP address and operation
    ///
    /// # Errors
    /// Returns an error if the BPF map update or delete operation fails.
    pub fn send_list_event(&self, event: IpListEvent) -> Result<()> {
        match event {
            IpListEvent::AddToList(ip_addr) => {
                let raw_ip = Self::ip_to_bytes(ip_addr);
                self.skel
                    .maps
                    .ip_list
                    .update(&raw_ip, &IP_LIST_VALUE, MapFlags::empty())?;
            }
            IpListEvent::RemoveFromList(ip_addr) => {
                let raw_ip = Self::ip_to_bytes(ip_addr);
                self.skel.maps.ip_list.delete(&raw_ip)?;
            }
        }
        Ok(())
    }

    /// Updates the active base filtering profile in the BPF map.
    ///
    /// # Arguments
    /// * `profile` — the new [`BaseProfile`] to apply
    ///
    /// # Errors
    /// Returns an error if the BPF map update fails.
    pub fn set_current_profile(&self, profile: BaseProfile) -> Result<()> {
        let raw_profile: u8 = profile.into();

        self.skel.maps.profile_mode.update(
            &PROFILE_MODE_KEY,
            std::slice::from_ref(&raw_profile),
            MapFlags::empty(),
        )?;

        Ok(())
    }

    /// Reads the current base filtering profile from the BPF map.
    ///
    /// # Returns
    /// `Some` with the current [`BaseProfile`], or `None` if the map key is absent.
    ///
    /// # Errors
    /// Returns an error if the BPF map lookup fails.
    pub fn get_current_profile(&self) -> Result<Option<BaseProfile>> {
        let raw_profile_option = self
            .skel
            .maps
            .profile_mode
            .lookup(&PROFILE_MODE_KEY, MapFlags::empty())?;
        Ok(raw_profile_option.map(|vec| BaseProfile::from(vec[0])))
    }

    /// Builds a ring buffer that polls the BPF events map and forwards parsed events.
    ///
    /// The returned [`RingBuffer`] must be polled in a loop (e.g. via [`RingBuffer::poll`])
    /// to receive connection events from the BPF layer.
    ///
    /// # Errors
    /// Returns an error if the ring buffer cannot be created from the BPF map.
    pub fn build_ringbuffer(&self) -> Result<RingBuffer<'_>> {
        let mut ringbuffer_builder = RingBufferBuilder::new();
        let trace_event_sender = self.sender.clone();
        ringbuffer_builder.add(&self.skel.maps.events, move |data: &[u8]| {
            let mut raw_event = netlogger_ebpf::types::event::default();
            match plain::copy_from_bytes(&mut raw_event, data) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Error when read package from ringbuffer {:?}", e);
                    return 0;
                }
            };
            let event = Self::parse_raw_event(raw_event);
            match trace_event_sender.send(event) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Error when send package to Sender {:?}", e);
                    return 0;
                }
            }
            0
        })?;
        Ok(ringbuffer_builder.build()?)
    }
}
