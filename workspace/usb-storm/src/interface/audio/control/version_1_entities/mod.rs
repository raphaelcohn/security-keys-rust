// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::Bytes;
use crate::VecExt;
use self::logical_audio_channel_cluster::Version1LogicalAudioChannelCluster;
use self::logical_audio_channel_cluster::Version1LogicalAudioChannelSpatialLocation;
use super::adjusted_index;
use super::adjusted_index_non_constant;
use super::entities::Entity;
use super::entities::Entities;
use super::entities::TerminalEntity;
use super::entities::UnitEntity;
use super::EntityDescriptors;
use super::EntityDescriptorParseError;
use super::logical_audio_channels::InputLogicalAudioChannelClusters;
use super::logical_audio_channels::LogicalAudioChannelNumber;
use super::parse_entity_descriptor;
use super::parse_p;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::terminal_types::InputTerminalType;
use super::terminal_types::OutputTerminalType;
use super::ChannelControlsByChannelNumber;
use enumflags2::bitflags;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::transmute;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::StringFinder;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::Alive;
use swiss_army_knife::non_zero::new_non_zero_u16;
use swiss_army_knife::non_zero::new_non_zero_usize;
use std::convert::Infallible;
use std::num::NonZeroU16;
use std::num::NonZeroUsize;
use super::DescriptorEntityMinimumLength;
use super::logical_audio_channels::LogicalAudioChannelClusterParseError;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::collections::WrappedIndexSet;
use crate::collections::WithCapacity;
use crate::collections::WrappedBitFlags;
use super::terminal_types::TerminalTypeParseError;


/// Logical audio channel cluster.
pub mod logical_audio_channel_cluster;


include!("DolbyProLogicMode.rs");
include!("parse_control_size.rs");
include!("ProcessType.rs");
include!("Version1AudioChannelFeatureControl.rs");
include!("Version1EntityDescriptorParseError.rs");
include!("Version1EntityDescriptors.rs");
include!("Version1ExtensionUnitEntity.rs");
include!("Version1FeatureUnitEntity.rs");
include!("Version1InputTerminalEntity.rs");
include!("Version1MixerUnitEntity.rs");
include!("Version1OutputTerminalEntity.rs");
include!("Version1ProcessingUnitEntity.rs");
include!("Version1SelectorUnitEntity.rs");
