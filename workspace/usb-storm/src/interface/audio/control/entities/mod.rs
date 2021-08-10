// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::Bytes;
use crate::VecExt;
use crate::additional_descriptors::DescriptorHeaderLength;
use crate::additional_descriptors::verify_remaining_bytes;
use crate::integers::u2;
use crate::interface::audio::Version3AudioDynamicStringDescriptorIdentifier;
use likely::unlikely;
use self::identifiers::ClockEntityIdentifier;
use self::identifiers::EntityIdentifier;
use self::identifiers::PowerDomainEntityIdentifier;
use self::identifiers::TerminalEntityIdentifier;
use self::identifiers::UnitEntityIdentifier;
use self::identifiers::UnitOrTerminalEntityIdentifier;
use self::terminal_types::InputTerminalType;
use self::terminal_types::OutputTerminalType;
use self::terminal_types::TerminalTypeParseError;
use super::AudioControlInterfaceAdditionalDescriptorParser;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::num::NonZeroU16;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::hash::Hash;
use serde::de::DeserializeOwned;
use std::mem::transmute;


/// Identifiers.
pub mod identifiers;


/// Terminal types.
pub mod terminal_types;


include!("adjusted_index.rs");
include!("ClockEntity.rs");
include!("Entity.rs");
include!("Entities.rs");
include!("PowerDomainEntity.rs");
include!("TerminalControls.rs");
include!("TerminalEntity.rs");
include!("TerminalEntityCommon.rs");
include!("UnitEntity.rs");
include!("Version3EntityDescriptorParseError.rs");
include!("Version3EntityDescriptors.rs");
