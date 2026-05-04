//! IP blocking control for the BPF layer.
//!
//! This module provides [`ProfileControl`] — forwards add and remove
//! commands to the BPF layer and maintains a local cache of addresses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::bpf::{BPFProgram, BaseProfile, IpListEvent};

use anyhow::Result;

/// Forwards add/remove commands to the BPF layer and maintains a local cache of managed addresses.
pub struct ProfileControl {
    ip_map: HashMap<IpAddr, bool>,
    bpf_program: Arc<BPFProgram>,
    current_profile: BaseProfile,
}

impl ProfileControl {
    /// Creates a new [`ProfileControl`] with an empty IP map.
    ///
    /// # Arguments
    /// * `bpf_program` — reference to the loaded BPF program
    /// * `current_profile` — initial base profile
    pub fn new(bpf_program: Arc<BPFProgram>, current_profile: BaseProfile) -> Self {
        Self {
            ip_map: HashMap::new(),
            bpf_program,
            current_profile,
        }
    }

    /// Adds an IP address to the BPF IP list and marks it in the local cache.
    ///
    /// # Errors
    /// Returns an error if the BPF map update fails.
    pub fn add(&mut self, ip: IpAddr) -> Result<()> {
        if let Err(err) = self.bpf_program.send_list_event(IpListEvent::AddToList(ip)) {
            tracing::error!("Error when send Block event for ip {} : {:?}", ip, err);
            Err(err)
        } else {
            self.ip_map.insert(ip, true);
            Ok(())
        }
    }

    /// Removes an IP address from the BPF IP list and marks it in the local cache.
    ///
    /// # Errors
    /// Returns an error if the BPF map delete fails.
    pub fn remove(&mut self, ip: IpAddr) -> Result<()> {
        if let Err(err) = self
            .bpf_program
            .send_list_event(IpListEvent::RemoveFromList(ip))
        {
            tracing::error!("Error when send Unblock event for ip {} : {:?}", ip, err);
            Err(err)
        } else {
            self.ip_map.insert(ip, false);
            Ok(())
        }
    }

    /// Checks whether an IP address is currently in the profile's IP list.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self.ip_map.get(ip) {
            Some(val) => *val,
            None => false,
        }
    }

    /// Returns all IP addresses currently in the profile.
    pub fn dump_profile_addrs(&self) -> Vec<IpAddr> {
        self.ip_map
            .iter()
            .filter(|entry| *entry.1)
            .map(|entry| *entry.0)
            .collect()
    }

    /// Returns the currently active base filtering profile.
    pub fn get_current_base_profile(&self) -> BaseProfile {
        self.current_profile
    }

    /// Sets the base filtering profile and propagates it to the BPF layer.
    ///
    /// The local cache is updated only if the BPF operation succeeds.
    ///
    /// # Errors
    /// Returns an error if the BPF map update fails.
    #[allow(dead_code)]
    pub fn set_current_base_profile(&mut self, profile: BaseProfile) -> Result<()> {
        let res = self.bpf_program.set_current_profile(profile);
        if res.is_ok() {
            self.current_profile = profile;
        }
        res
    }
}
