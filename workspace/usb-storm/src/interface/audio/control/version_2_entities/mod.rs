// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::collections::WithCapacity;
use crate::collections::WrappedBitFlags;
use crate::collections::WrappedIndexSet;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::StringFinder;
use enumflags2::BitFlag;
use likely::unlikely;
use self::logical_audio_channel_cluster::Version2LogicalAudioChannelCluster;
use self::logical_audio_channel_cluster::Version2LogicalAudioChannelClusterParseError;
use self::logical_audio_channel_cluster::Version2LogicalAudioChannelSpatialLocation;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::size_of;
use std::mem::transmute;
use std::num::NonZeroU16;
use super::ChannelControlsByChannelNumber;
use super::Control;
use super::DescriptorEntityMinimumLength;
use super::DolbyProLogicMode;
use super::DolbyProLogicModeConversionError;
use super::EntityDescriptorParseError;
use super::EntityDescriptors;
use super::entities::ClockEntity;
use super::entities::Entities;
use super::entities::Entity;
use super::entities::TerminalEntity;
use super::entities::UnitEntity;
use super::entity_identifiers::ClockEntityIdentifier;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::entity_index;
use super::entity_index_non_constant;
use super::logical_audio_channels::InputLogicalAudioChannelClusters;
use super::logical_audio_channels::LogicalAudioChannelCluster;
use super::logical_audio_channels::LogicalAudioChannelClusterParseError;
use super::logical_audio_channels::LogicalAudioChannelSpatialLocation;
use super::parse_entity_descriptor;
use super::parse_p;
use super::parse_process_type_modes;
use super::validate_process_type_empty;
use super::validate_process_type_not_empty;
use super::terminal_types::InputTerminalType;
use super::terminal_types::OutputTerminalType;
use super::terminal_types::TerminalTypeParseError;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u16;


/// Effect.
pub mod effect;


/// Logical audio channel cluster.
pub mod logical_audio_channel_cluster;

include!("ClockType.rs");
include!("parse_controls_by_channel_number.rs");
include!("Version2AudioChannelFeatureControls.rs");
include!("Version2EntityDescriptorParseError.rs");
include!("Version2EntityDescriptors.rs");
include!("Version2FeatureUnitEntity.rs");
include!("Version2FeatureUnitEntityParseError.rs");
include!("Version2FeatureUnitEntityChannelControlParseError.rs");
include!("Version2InputTerminalEntity.rs");
include!("Version2MixerUnitEntity.rs");
include!("Version2MultiplierClockEntity.rs");
include!("Version2OutputTerminalEntity.rs");
include!("Version2ProcessType.rs");
include!("Version2ProcessTypeParseError.rs");
include!("Version2ProcessingUnitEntity.rs");
include!("Version2ProcessingUnitEntityParseError.rs");
include!("Version2SamplingRateConverterUnitEntity.rs");
include!("Version2SelectorClockEntity.rs");
include!("Version2SelectorUnitEntity.rs");
include!("Version2SourceClockEntity.rs");
