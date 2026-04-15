//! IP blocking control for the BPF layer.
//!
//! This module provides [`BlockControl`] — forwards block and unblock
//! commands to the BPF layer and maintains a local cache of blocked addresses.

use std::collections::HashMap;
use std::{net::IpAddr, sync::mpsc};

use crate::bpf::BlockEvent;

/// Forwards block and unblock commands to the BPF layer and maintains a local cache of blocked addresses.
#[derive(Debug)]
pub struct BlockControl {
    ip_map: HashMap<IpAddr, bool>,
    tx: mpsc::Sender<BlockEvent>,
}

impl BlockControl {
    /// Creates a new [`BlockControl`] with the given command sender.
    ///
    /// # Arguments
    /// * `tx` — sender for block/unblock commands to the BPF layer
    pub fn new(tx: mpsc::Sender<BlockEvent>) -> BlockControl {
        BlockControl {
            tx,
            ip_map: HashMap::new(),
        }
    }

    /// Sends a block command for the given IP address to the BPF layer.
    ///
    /// Updates the local cache on success. Logs an error if the channel is closed.
    ///
    /// # Arguments
    /// * `ip` — IP address to block
    pub fn block(&mut self, ip: IpAddr) {
        if let Err(err) = self.tx.send(BlockEvent::Block(ip)) {
            tracing::error!("Error when send Block event for ip {} : {:?}", ip, err);
        } else {
            self.ip_map.insert(ip, true);
        }
    }

    /// Removes the block for the given IP address in the BPF layer.
    ///
    /// Updates the local cache on success. Logs an error if the channel is closed.
    ///
    /// # Arguments
    /// * `ip` — IP address to unblock
    pub fn unblock(&mut self, ip: IpAddr) {
        if let Err(err) = self.tx.send(BlockEvent::Unblock(ip)) {
            tracing::error!("Error when send Unblock event for ip {} : {:?}", ip, err);
        } else {
            self.ip_map.insert(ip, false);
        }
    }

    /// Returns `true` if the given IP address is currently blocked.
    ///
    /// Checks the local cache without querying the BPF layer.
    ///
    /// # Arguments
    /// * `ip` — IP address to check
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        match self.ip_map.get(ip) {
            Some(res) => *res,
            None => false,
        }
    }
}
