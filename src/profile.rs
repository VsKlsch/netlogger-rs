use std::net::IpAddr;

use crate::bpf::BaseProfile;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct ProfileV1 {
    pub ip_list: Vec<IpAddr>,
    pub base_profile: BaseProfile,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum Profile {
    #[serde(rename = "1")]
    V1(ProfileV1),
}

pub type ActualProfile = ProfileV1;

pub struct ProfileFilter {
    pub name: &'static str,
    pub extensions: &'static [&'static str],
}

pub trait ProfileConverter {
    const DEFAULT_PROFILE_NAME: &'static str;
    const PROFILE_EXTENSIONS_NAME: &'static str;
    const PROFILE_EXTENSIONS: &'static [&'static str];

    fn serialize(&self, profile: &Profile) -> Result<String>;
    fn deserialize(&self, raw_profile: &str) -> Result<ActualProfile>;
}

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
    fn from(value: ProfileV1) -> Self {
        Self::V1(value)
    }
}
