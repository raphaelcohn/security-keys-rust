// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::class_and_protocol::AudioProtocol;
use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::collections::WithCapacity;
use crate::collections::WrappedBitFlags;
use crate::collections::WrappedHashSet;
use crate::collections::WrappedIndexSet;
use crate::control_transfers::descriptors::MinimumStandardUsbDescriptorLength;
use crate::interface::audio::CS_INTERFACE;
use crate::descriptors::{DescriptorHeaderLength, DescriptorSubType};
use crate::descriptors::DescriptorParser;
use crate::descriptors::DescriptorType;
use crate::descriptors::verify_remaining_bytes;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;
use crate::device::DeadOrAlive;
use crate::device::DeviceConnection;
use crate::interface::InterfaceNumber;
use crate::interface::MaximumNumberOfInterfaces;
use crate::serde::TryReserveErrorRemote;
use crate::version::Version;
use crate::version::VersionParseError;
use likely::unlikely;
use self::entities::Entities;
use self::entities::Entity;
use self::entity_identifiers::EntityIdentifier;
use self::logical_audio_channels::LogicalAudioChannelCluster;
use self::logical_audio_channels::LogicalAudioChannelNumber;
use self::logical_audio_channels::LogicalAudioChannelSpatialLocation;
use self::version_1_entities::Version1EntityDescriptorParseError;
use self::version_1_entities::Version1EntityDescriptors;
use self::version_1_entities::logical_audio_channel_cluster::Version1LogicalAudioChannelSpatialLocation;
use self::version_2_entities::Version2EntityDescriptorParseError;
use self::version_2_entities::Version2EntityDescriptors;
use self::version_2_entities::logical_audio_channel_cluster::Version2LogicalAudioChannelSpatialLocation;
use self::version_3_entities::Version3EntityDescriptorParseError;
use self::version_3_entities::Version3EntityDescriptors;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::convert::TryFrom;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::hash::Hash;
use std::mem::size_of;
use std::num::NonZeroU8;
use super::Control;
use swiss_army_knife::get_unchecked::GetUnchecked;


/// Entities.
pub mod entities;


/// Entity identifiers.
pub mod entity_identifiers;


/// Logical audio channels.
pub mod logical_audio_channels;


/// Terminal types.
pub mod terminal_types;


/// Version 1 entities.
pub mod version_1_entities;


/// Version 2 entities.
pub mod version_2_entities;


/// Version 3 entities.
pub mod version_3_entities;


include!("AudioControlInterfaceExtraDescriptor.rs");
include!("AudioControlInterfaceExtraDescriptorParseError.rs");
include!("AudioControlInterfaceExtraDescriptorParser.rs");
include!("AudioFunctionCategory.rs");
include!("ChannelControlsByChannelNumber.rs");
include!("DescriptorEntityMinimumLength.rs");
include!("DescriptorSubTypeAndEntityIdentifierLength.rs");
include!("DolbyProLogicMode.rs");
include!("DolbyProLogicModeConversionError.rs");
include!("EntityDescriptorParseError.rs");
include!("EntityDescriptors.rs");
include!("entity_index.rs");
include!("entity_index_non_constant.rs");
include!("parse_entity_descriptor.rs");
include!("parse_p.rs");
include!("parse_process_type_modes.rs");
include!("validate_process_type_not_empty.rs");
include!("validate_process_type_empty.rs");
