//! IP blocking control for the BPF layer.
//!
//! This module provides [`BlockControl`] — forwards block and unblock
//! commands to the BPF layer and maintains a local cache of blocked addresses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::bpf::{BPFProgram, BaseProfile, IpListEvent};

use anyhow::Result;

/// Forwards block and unblock commands to the BPF layer and maintains a local cache of blocked addresses.
pub struct ProfileControl {
    ip_map: HashMap<IpAddr, bool>,
    bpf_program: Arc<BPFProgram>,
    current_profile: BaseProfile,
}

impl ProfileControl {
    pub fn new(bpf_program: Arc<BPFProgram>, current_profile: BaseProfile) -> Self {
        Self {
            ip_map: HashMap::new(),
            bpf_program,
            current_profile,
        }
    }

    pub fn add(&mut self, ip: IpAddr) -> Result<()> {
        if let Err(err) = self.bpf_program.send_list_event(IpListEvent::AddToList(ip)) {
            tracing::error!("Error when send Block event for ip {} : {:?}", ip, err);
            Err(err)
        } else {
            self.ip_map.insert(ip, true);
            Ok(())
        }
    }

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

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self.ip_map.get(ip) {
            Some(val) => *val,
            None => false,
        }
    }

    pub fn dump_profile_addrs(&self) -> Vec<IpAddr> {
        self.ip_map
            .iter()
            .filter(|entry| *entry.1)
            .map(|entry| entry.0.clone())
            .collect()
    }

    pub fn get_current_base_profile(&self) -> BaseProfile {
        self.current_profile
    }

    #[allow(dead_code)]
    pub fn set_current_base_profile(&mut self, profile: BaseProfile) -> Result<()> {
        let res = self.bpf_program.set_current_profile(profile);
        if res.is_ok() {
            self.current_profile = profile;
        }
        res
    }
}
