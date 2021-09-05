// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::device::DeadOrAlive;
use super::super::entity_index_non_constant;
use super::super::logical_audio_channels::LogicalAudioChannelClusterParseError;
use super::super::logical_audio_channels::LogicalAudioChannelCluster;
use super::super::logical_audio_channels::LogicalAudioChannelSpatialLocation;
use crate::device::DeviceConnection;
use enumflags2::bitflags;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;
use crate::serde::InfallibleError;


include!("Version1LogicalAudioChannelCluster.rs");
include!("Version1LogicalAudioChannelSpatialLocation.rs");
