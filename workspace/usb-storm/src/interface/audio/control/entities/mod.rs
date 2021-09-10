// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::EntityDescriptorParseError;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::ClockEntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use crate::collections::VecExt;
use crate::collections::WrappedHashMap;
use crate::device::DeadOrAlive;
use crate::device::DeviceConnection;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::error;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::NonZeroU8;
use crate::string::LocalizedStrings;
use crate::interface::audio::control::terminal_types::{OutputTerminalType, InputTerminalType};
use crate::interface::audio::control::entity_identifiers::UnitOrTerminalEntityIdentifier;


include!("ClockEntity.rs");
include!("DescribedEntity.rs");
include!("Entities.rs");
include!("Entity.rs");
include!("ExtensionUnitEntity.rs");
include!("FeatureUnitEntity.rs");
include!("InputTerminalEntity.rs");
include!("MixerUnitEntity.rs");
include!("MultiplierClockEntity.rs");
include!("OutputTerminalEntity.rs");
include!("ProcessingUnitEntity.rs");
include!("SamplingRateConverterUnitEntity.rs");
include!("SelectorClockEntity.rs");
include!("SelectorUnitEntity.rs");
include!("SourceClockEntity.rs");
include!("TerminalEntity.rs");
include!("UnitEntity.rs");
include!("Version1Entity.rs");
include!("Version2Entity.rs");
include!("Version3Entity.rs");
