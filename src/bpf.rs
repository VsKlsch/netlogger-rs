//! Userspace of BPF Layer of netlogger-rs
//!
//! This module provides:
//! - [`AddressFamily`] - public enum for event's request net family
//! - [`Event`] - structure contains information about connection event
//! - [`BlockEvent`] - structure contains information about block event
//! - [`BPFWorker`] - main structure for BPF layer

mod program_skel;

use std::error::Error;
use std::fmt::Display;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::mpsc;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject, RingBuffer, RingBufferBuilder, Link};

use anyhow::Result;

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

#[derive(Debug, Clone)]
pub enum L4Protocol{
    Tcp,
    Udp,
    Other(u8)
}

impl Display for L4Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Other(num) => write!(f, "Other({})", num)
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

#[derive(Debug, Clone)]
pub enum ParseStatus{
    Success,
    ErrorAtReadFamily,
    ErrorAtReadSockaddr,
    Partial,
    Other(u8)
}

impl Display for ParseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::ErrorAtReadFamily => write!(f, "Error at read family"),
            Self::ErrorAtReadSockaddr => write!(f, "Error ad read Sockaddr"),
            Self::Partial => write!(f, "Partial"),
            Self::Other(num) => write!(f, "Other({})", num)
        }
    }
}

impl From<u8> for ParseStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::ErrorAtReadFamily,
            2 => Self::ErrorAtReadSockaddr,
            3 => Self::Partial,
            v => Self::Other(v)
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventStatus{
    Unknown,
    Block,
    Pass,
    Other(u8)
}

impl Display for EventStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Block => write!(f, "Block"),
            Self::Pass => write!(f, "Pass"),
            Self::Other(num) => write!(f, "Other({})", num)
        }
    }
}

impl From<u8> for EventStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Block,
            1 => Self::Pass,
            2 => Self::Unknown,
            v => Self::Other(v)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BaseProfile{
    DenyAll,
    PassAll,
    Other(u8)
}

impl Display for BaseProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DenyAll => write!(f, "Deny All"),
            Self::PassAll => write!(f, "Pass All"),
            Self::Other(num) => write!(f, "Other({})", num)
        }
    }
}

impl From<u8> for BaseProfile {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::DenyAll,
            1 => Self::PassAll,
            v => Self::Other(v)
        }
    }
}

impl Into<u8> for BaseProfile {
    fn into(self) -> u8 {
        match self {
            BaseProfile::DenyAll => 0u8,
            BaseProfile::PassAll => 1u8,
            BaseProfile::Other(v) => v,
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

    /// Event status may be Block or Pass
    pub event_status: EventStatus,

    /// Parse stauts Succes, Partial or error
    pub parse_status: ParseStatus,

    /// L4 type
    pub l4_protocol: L4Protocol    
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

#[derive(Debug, Clone)]
pub enum IpListEvent {
    AddToList(IpAddr),

    RemoveFromList(IpAddr),
}

#[derive(Debug, Clone, Copy)]
pub enum BPFError{
    RodataRetrievengError(&'static str)
}

impl Display for BPFError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self{
            BPFError::RodataRetrievengError(err) => write!(f, "Error when create BPFProgram: {}", err),
        }
    }
}

impl Error for BPFError{}

pub struct BPFProgram {
    _link_con4: Link,
    _link_con6: Link,
    _link_sendmsg4: Link,
    _link_sendmsg6: Link,
    skel: ProgramSkel<'static>,
    _open_object: Pin<Box<MaybeUninit<OpenObject>>>,
    sender: mpsc::Sender<Event>
}

impl BPFProgram{
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
        let event_status = EventStatus::from(raw_event.event_status);
        let parse_status = ParseStatus::from(raw_event.parse_status);
        let l4_protocol = L4Protocol::from(raw_event.l4_protocol);

        Event {
            ip,
            pid: raw_event.pid,
            tgid: raw_event.tgid,
            syscall_id: raw_event.syscall_id,
            family,
            port: raw_event.port,
            timestamp: raw_event.timestamp,
            event_status,
            parse_status,
            l4_protocol
        }
    }


    pub fn new(target_pid: u32, base_profile: BaseProfile, trace_event_sender: mpsc::Sender<Event>) -> Result<BPFProgram> {
        let mut program_skel_builder = ProgramSkelBuilder::default();

        #[cfg(debug_assertions)]
        program_skel_builder.obj_builder.debug(true);

        let mut open_object = Box::pin(MaybeUninit::uninit());
        let mut open_skel = program_skel_builder.open(&mut open_object)?;
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut().ok_or(BPFError::RodataRetrievengError("Error retrieveng ROData"))?;

        rodata.fallback_profile = base_profile.into();
        rodata.initial_target_tgid = target_pid;

        let skel = open_skel.load()?;

        // SAFETY: The `skel` object has an effective lifetime of `open_object`,
        // but we change it to `static` so that they can coexist in the same structure BPFProgram.
        // Rust's reference mechanism ensures that `skel` will be destroyed before `_open_object`.
        let mut skel: ProgramSkel<'static> = unsafe{ std::mem::transmute(skel) };
        let cp_value: [u8;1] = [base_profile.into()];
        skel.maps.profile_mode.update(&PROFILE_MODE_KEY, &cp_value, libbpf_rs::MapFlags::empty())?;

        skel.attach()?;

        tracing::info!("[BPF Program] Tracepoint successfully attached");

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
        
        Ok(BPFProgram{
            _link_con4: link_con4,
            _link_con6: link_con6,
            _link_sendmsg4: link_sendmsg4,
            _link_sendmsg6: link_sendmsg6,
            _open_object: open_object,
            skel,
            sender: trace_event_sender
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

    pub fn send_list_event(&self, event: IpListEvent) -> Result<()> {
        match event{
            IpListEvent::AddToList(ip_addr) => {
                let raw_ip = Self::ip_to_bytes(ip_addr);
                self.skel.maps.ip_list.update(&raw_ip, &IP_LIST_VALUE, MapFlags::empty())?;
            },
            IpListEvent::RemoveFromList(ip_addr) => {
                let raw_ip = Self::ip_to_bytes(ip_addr);
                self.skel.maps.ip_list.delete(&raw_ip)?;
            },
        }
        Ok(())
    }

    pub fn set_current_profile(&self, profile: BaseProfile) -> Result<()> {
        let raw_profile: u8 = profile.into();

        self.skel.maps.profile_mode.update(&PROFILE_MODE_KEY, std::slice::from_ref(&raw_profile), MapFlags::empty())?;

        Ok(()) 
    }

    pub fn get_current_profile(&self) -> Result<Option<BaseProfile>> {
        let raw_profile_option = self.skel.maps.profile_mode.lookup(&PROFILE_MODE_KEY, MapFlags::empty())?;
        Ok(
            match raw_profile_option {
                Some(vec) => Some(BaseProfile::from(vec[0])),
                None => None
            }
        )
    }

    pub fn build_ringbuffer(&self) -> Result<RingBuffer<'_>>{
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