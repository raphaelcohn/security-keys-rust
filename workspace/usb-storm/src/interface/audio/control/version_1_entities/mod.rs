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
use enumflags2::bitflags;
use likely::unlikely;
use self::logical_audio_channel_cluster::Version1LogicalAudioChannelCluster;
use self::logical_audio_channel_cluster::Version1LogicalAudioChannelSpatialLocation;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::convert::Infallible;
use std::convert::TryFrom;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::size_of;
use std::mem::transmute;
use std::num::NonZeroU16;
use std::num::NonZeroUsize;
use super::ChannelControlsByChannelNumber;
use super::DescriptorEntityMinimumLength;
use super::DolbyProLogicMode;
use super::DolbyProLogicModeConversionError;
use super::EntityDescriptorParseError;
use super::EntityDescriptors;
use super::entities::Entities;
use super::entities::Entity;
use super::entities::TerminalEntity;
use super::entities::UnitEntity;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::entity_index;
use super::entity_index_non_constant;
use super::logical_audio_channels::InputLogicalAudioChannelClusters;
use super::logical_audio_channels::LogicalAudioChannelClusterParseError;
use super::logical_audio_channels::LogicalAudioChannelNumber;
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
use swiss_army_knife::non_zero::new_non_zero_usize;


/// Logical audio channel cluster.
pub mod logical_audio_channel_cluster;


include!("parse_control_size.rs");
include!("Version1AudioChannelFeatureControl.rs");
include!("Version1EntityDescriptorParseError.rs");
include!("Version1EntityDescriptors.rs");
include!("Version1ExtensionUnitEntity.rs");
include!("Version1ExtensionUnitEntityParseError.rs");
include!("Version1FeatureUnitEntity.rs");
include!("Version1FeatureUnitEntityParseError.rs");
include!("Version1InputTerminalEntity.rs");
include!("Version1InputTerminalEntityParseError.rs");
include!("Version1MixerUnitEntity.rs");
include!("Version1MixerUnitEntityParseError.rs");
include!("Version1OutputTerminalEntity.rs");
include!("Version1OutputTerminalEntityParseError.rs");
include!("Version1ProcessingUnitEntity.rs");
include!("Version1ProcessingUnitEntityParseError.rs");
include!("Version1ProcessType.rs");
include!("Version1ProcessTypeParseError.rs");
include!("Version1SelectorUnitEntity.rs");
include!("Version1SelectorUnitEntityParseError.rs");
