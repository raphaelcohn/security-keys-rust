// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::VC_DESCRIPTOR_UNDEFINED;
use super::VC_HEADER;
use super::VC_INPUT_TERMINAL;
use super::VC_OUTPUT_TERMINAL;
use super::VC_SELECTOR_UNIT;
use super::VC_PROCESSING_UNIT;
use super::VC_EXTENSION_UNIT;
use super::entity_identifiers::EntityIdentifier;
use crate::collections::WrappedHashMap;
use crate::collections::Bytes;
use crate::collections::WrappedHashSet;
use crate::collections::VecExt;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::DescriptorSubType;
use crate::device::DeadOrAlive;
use crate::device::DeviceConnection;
use crate::interface::video::CS_INTERFACE;
use crate::version::Version;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroU8;
use std::hash::Hash;
use serde::de::DeserializeOwned;
use crate::device::DeadOrAlive::Alive;
use std::mem::size_of;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::serde::TryReserveErrorRemote;
use crate::interface::video::control::entities::terminal::input::InputTerminalEntity;
use crate::interface::video::control::entities::terminal::input::InputTerminalEntityParseError;
use crate::interface::video::control::entities::terminal::output::OutputTerminalEntity;
use crate::interface::video::control::entities::terminal::output::OutputTerminalEntityParseError;
use crate::interface::video::control::entities::unit::selector::SelectorUnitEntity;
use crate::interface::video::control::entities::unit::selector::SelectorUnitEntityParseError;
use crate::interface::video::control::entities::unit::processing::ProcessingUnitEntity;
use crate::interface::video::control::entities::unit::processing::ProcessingUnitEntityParseError;
use crate::interface::video::control::entities::unit::extension::ExtensionUnitEntity;
use crate::interface::video::control::entities::unit::extension::ExtensionUnitEntityParseError;
use crate::string::LocalizedStrings;
use crate::interface::video::control::entities::unit::encoding::EncodingUnitEntityParseError;


/// Terminal entity descriptors.
pub mod terminal;


/// Unit entity descriptors.
pub mod unit;


include!("CommonEntityDescriptorParseError.rs");
include!("DescriptorEntityMinimumLength.rs");
include!("DescriptorSubTypeAndEntityIdentifierLength.rs");
include!("Entities.rs");
include!("Entity.rs");
include!("entity_index.rs");
include!("entity_index_non_constant.rs");
include!("EntityDescriptors.rs");
include!("EntityDescriptorParseError.rs");
include!("WithSourceEntity.rs");
