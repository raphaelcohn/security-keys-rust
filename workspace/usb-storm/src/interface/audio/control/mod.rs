// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::entity_identifiers::ClockEntityIdentifier;
use self::entity_identifiers::EntityIdentifier;
use self::entity_identifiers::TerminalEntityIdentifier;
use self::entity_identifiers::UnitEntityIdentifier;
use self::entity_identifiers::UnitOrTerminalEntityIdentifier;
use crate::Bytes;
use crate::VecExt;
use crate::additional_descriptors::AdditionalDescriptorParser;
use crate::additional_descriptors::DescriptorHeaderLength;
use crate::additional_descriptors::DescriptorType;
use crate::additional_descriptors::verify_remaining_bytes;
use crate::class_and_protocol::AudioProtocol;
use crate::integers::u2;
use crate::interface::InterfaceNumber;
use crate::interface::MaximumNumberOfInterfaces;
use crate::version::Version;
use crate::version::VersionParseError;
use indexmap::set::IndexSet;
use likely::unlikely;
use self::version_1_entities::Version1EntityDescriptorParseError;
use self::version_2_entities::Version2EntityDescriptorParseError;
use self::version_3_entities::Version3EntityDescriptorParseError;
use self::version_3_entities::Version3EntityDescriptors;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::size_of;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::hash::Hash;
use std::ops::Deref;
use serde::de::DeserializeOwned;
use crate::string::StringFinder;
use crate::string::LocalizedStrings;
use crate::string::GetLocalizedStringError;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;
use std::num::NonZeroU8;
use enumflags2::{BitFlags, BitFlag};
use swiss_army_knife::non_zero::new_non_zero_u8;


/// Entity identifiers.
pub mod entity_identifiers;


/// Terminal types.
pub mod terminal_types;


/// Version 1 entities.
pub mod version_1_entities;


/// Version 2 entities.
pub mod version_2_entities;


/// Version 3 entities.
pub mod version_3_entities;


include!("adjusted_index.rs");
include!("adjusted_index_non_constant.rs");
include!("AudioControlInterfaceAdditionalDescriptor.rs");
include!("AudioControlInterfaceAdditionalDescriptorParseError.rs");
include!("AudioControlInterfaceAdditionalDescriptorParser.rs");
include!("AudioFunctionCategory.rs");
include!("ClockEntity.rs");
include!("DescriptorEntityMinimumLength.rs");
include!("DescriptorSubTypeAndEntityIdentifierLength.rs");
include!("Entities.rs");
include!("Entity.rs");
include!("EntityDescriptorParseError.rs");
include!("EntityDescriptors.rs");
include!("InputLogicalAudioChannelClusters.rs");
include!("InputPinNumber.rs");
include!("LogicalAudioChannel.rs");
include!("LogicalAudioChannelCluster.rs");
include!("LogicalAudioChannelNumber.rs");
include!("LogicalAudioChannelClusterParseError.rs");
include!("LogicalAudioChannelSpatialLocation.rs");
include!("parse_entity_descriptor.rs");
include!("parse_p.rs");
include!("TerminalEntity.rs");
include!("UnitEntity.rs");
