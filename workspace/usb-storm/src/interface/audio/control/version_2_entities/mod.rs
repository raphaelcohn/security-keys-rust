// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::Bytes;
use crate::VecExt;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::StringFinder;
use likely::unlikely;
use std::collections::HashSet;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::transmute;
use super::ClockEntity;
use super::DescriptorEntityMinimumLength;
use super::Entities;
use super::Entity;
use super::EntityDescriptorParseError;
use super::EntityDescriptors;
use super::TerminalEntity;
use super::UnitEntity;
use super::adjusted_index;
use super::adjusted_index_non_constant;
use super::entity_identifiers::ClockEntityIdentifier;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::parse_entity_descriptor;
use super::parse_p;


include!("ClockType.rs");
include!("Control.rs");
include!("Version2EntityDescriptorParseError.rs");
include!("Version2EntityDescriptors.rs");
include!("Version2MultiplierClockEntity.rs");
include!("Version2SamplingRateConverterUnitEntity.rs");
include!("Version2SelectorClockEntity.rs");
include!("Version2SourceClockEntity.rs");
