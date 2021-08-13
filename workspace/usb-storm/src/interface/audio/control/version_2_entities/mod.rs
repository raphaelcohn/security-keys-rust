// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::StringFinder;
use self::logical_audio_channel_cluster::Version2LogicalAudioChannelCluster;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::size_of;
use std::mem::transmute;
use super::Control;
use super::DescriptorEntityMinimumLength;
use super::entities::ClockEntity;
use super::entities::Entities;
use super::entities::Entity;
use super::entities::UnitEntity;
use super::entities::TerminalEntity;
use super::EntityDescriptorParseError;
use super::EntityDescriptors;
use super::entity_index;
use super::entity_index_non_constant;
use super::entity_identifiers::ClockEntityIdentifier;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::parse_entity_descriptor;
use super::ChannelControlsByChannelNumber;
use super::parse_p;
use self::logical_audio_channel_cluster::Version2LogicalAudioChannelClusterParseError;
use super::logical_audio_channels::LogicalAudioChannelClusterParseError;
use super::logical_audio_channels::InputLogicalAudioChannelClusters;
use crate::interface::audio::control::terminal_types::{InputTerminalType, TerminalTypeParseError, OutputTerminalType};


/// Logical audio channel cluster.
pub mod logical_audio_channel_cluster;


include!("ClockType.rs");
include!("Version2AudioChannelFeatureControls.rs");
include!("Version2EntityDescriptorParseError.rs");
include!("Version2EntityDescriptors.rs");
include!("Version2FeatureUnitEntity.rs");
include!("Version2InputTerminalEntity.rs");
include!("Version2MixerUnitEntity.rs");
include!("Version2MultiplierClockEntity.rs");
include!("Version2OutputTerminalEntity.rs");
include!("Version2SamplingRateConverterUnitEntity.rs");
include!("Version2SelectorClockEntity.rs");
include!("Version2SelectorUnitEntity.rs");
include!("Version2SourceClockEntity.rs");
