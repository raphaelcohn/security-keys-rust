// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::interface::audio::Control;
use crate::interface::audio::control::DescriptorEntityMinimumLength;
use crate::interface::audio::control::entities::{UnitEntity, Entity};
use crate::interface::audio::control::entity_identifiers::EntityIdentifier;
use crate::interface::audio::control::entity_identifiers::UnitEntityIdentifier;
use crate::interface::audio::control::entity_index_non_constant;
use crate::interface::audio::control::logical_audio_channels::{InputLogicalAudioChannelClusters, LogicalAudioChannelClusterParseError};
use crate::interface::audio::control::parse_p;
use crate::interface::audio::control::version_2_entities::Version2EntityDescriptorParseError;
use crate::interface::audio::control::version_2_entities::Version2EntityDescriptors;
use crate::interface::audio::control::version_2_entities::logical_audio_channel_cluster::{Version2LogicalAudioChannelCluster, Version2LogicalAudioChannelClusterParseError};
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::device::DeviceConnection;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::transmute;


include!("Version2MixerUnitEntity.rs");
include!("Version2MixerUnitEntityParseError.rs");
