// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::collections::WrappedBitFlags;
use crate::collections::WrappedIndexSet;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::interface::audio::control::DescriptorEntityMinimumLength;
use crate::interface::audio::control::DolbyProLogicMode;
use crate::interface::audio::control::DolbyProLogicModeConversionError;
use crate::interface::audio::control::entities::Entity;
use crate::interface::audio::control::entities::UnitEntity;
use crate::interface::audio::control::entity_identifiers::EntityIdentifier;
use crate::interface::audio::control::entity_identifiers::UnitEntityIdentifier;
use crate::interface::audio::control::entity_index;
use crate::interface::audio::control::logical_audio_channels::InputLogicalAudioChannelClusters;
use crate::interface::audio::control::logical_audio_channels::LogicalAudioChannelClusterParseError;
use crate::interface::audio::control::parse_p;
use crate::interface::audio::control::parse_process_type_modes;
use crate::interface::audio::control::validate_process_type_empty;
use crate::interface::audio::control::validate_process_type_not_empty;
use crate::interface::audio::control::version_1_entities::Version1EntityDescriptorParseError;
use crate::interface::audio::control::version_1_entities::logical_audio_channel_cluster::Version1LogicalAudioChannelCluster;
use crate::interface::audio::control::version_1_entities::logical_audio_channel_cluster::Version1LogicalAudioChannelSpatialLocation;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::StringFinder;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
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
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u16;


include!("Version1ProcessingUnitEntity.rs");
include!("Version1ProcessingUnitEntityParseError.rs");
include!("Version1ProcessType.rs");
include!("Version1ProcessTypeParseError.rs");
