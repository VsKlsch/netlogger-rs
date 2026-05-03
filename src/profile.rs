//! Profile serialization, deserialization and conversion.
//!
//! This module provides:
//! - [`ProfileV1`] / [`ActualProfile`] — version-1 profile data model
//! - [`Profile`] — versioned profile enum
//! - [`ProfileConverter`] — trait for serializing/deserializing profiles
//! - [`JsonProfileConverter`] — JSON implementation of [`ProfileConverter`]

use std::net::IpAddr;

use crate::bpf::BaseProfile;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Version 1 of the netlogger profile data model.
///
/// Contains a list of IP addresses managed by the user and the base filtering
/// profile (pass-all or deny-all).
#[derive(Serialize, Deserialize, Default)]
pub struct ProfileV1 {
    /// List of IP addresses to block or allow (depending on base profile).
    pub ip_list: Vec<IpAddr>,
    /// Base profile mode: deny all connections by default or pass all.
    pub base_profile: BaseProfile,
}

/// Versioned profile enum for forward-compatible deserialization.
///
/// The `version` field in the serialized format determines which variant is used.
#[derive(Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum Profile {
    /// Profile data model version 1.
    #[serde(rename = "1")]
    V1(ProfileV1),
}

/// Alias for the currently active profile data model version.
///
/// Currently points to [`ProfileV1`].
pub type ActualProfile = ProfileV1;

/// Metadata describing a profile file format for file dialog filters.
pub struct ProfileFilter {
    /// Human-readable name of the format (e.g. "JSON").
    pub name: &'static str,
    /// File extensions associated with this format (e.g. `["json"]`).
    pub extensions: &'static [&'static str],
}

/// Trait for serializing and deserializing netlogger profiles.
///
/// Implementors provide format-specific conversion between the in-memory
/// [`Profile`] / [`ActualProfile`] types and their string representation.
pub trait ProfileConverter {
    /// Default file name (without path) used for the "Save" dialog.
    const DEFAULT_PROFILE_NAME: &'static str;
    /// Human-readable name for the list of file extensions.
    const PROFILE_EXTENSIONS_NAME: &'static str;
    /// List of file extensions associated with this format.
    const PROFILE_EXTENSIONS: &'static [&'static str];

    /// Serializes a [`Profile`] into its string representation.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    fn serialize(&self, profile: &Profile) -> Result<String>;

    /// Deserializes a raw profile string into [`ActualProfile`].
    ///
    /// # Errors
    /// Returns an error if the input is not a valid profile in this format.
    fn deserialize(&self, raw_profile: &str) -> Result<ActualProfile>;
}

/// [`ProfileConverter`] implementation using JSON (serde_json).
///
/// Profiles are serialized as pretty-printed JSON and saved with the
/// `.json` extension.
#[derive(Default)]
pub struct JsonProfileConverter;

impl ProfileConverter for JsonProfileConverter {
    const DEFAULT_PROFILE_NAME: &'static str = "profile.json";
    const PROFILE_EXTENSIONS_NAME: &'static str = "JSON";
    const PROFILE_EXTENSIONS: &'static [&'static str] = &["json"];

    fn serialize(&self, profile: &Profile) -> Result<String> {
        Ok(serde_json::to_string_pretty(profile)?)
    }

    fn deserialize(&self, raw_profile: &str) -> Result<ActualProfile> {
        match serde_json::from_str::<Profile>(raw_profile)? {
            Profile::V1(profile_v1) => Ok(profile_v1),
        }
    }
}

impl From<ProfileV1> for Profile {
    /// Wraps a [`ProfileV1`] into the versioned [`Profile`] enum.
    fn from(value: ProfileV1) -> Self {
        Self::V1(value)
    }
}
