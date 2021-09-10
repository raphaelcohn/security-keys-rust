// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::unlikely;
use serde::{Deserialize, Serializer, Deserializer};
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::version::Version;
use crate::interface::video::control::entities::Entity;
use crate::interface::video::control::entities::entity_index;
use crate::interface::video::control::entities::entity_index_non_constant;
use crate::interface::video::control::entity_identifiers::UnitEntityIdentifier;
use crate::interface::video::control::entity_identifiers::EntityIdentifier;
use crate::device::{DeviceConnection, DeadOrAlive};
use crate::interface::video::control::entities::unit::{Sources, WithSourcesUnitEntity};
use crate::interface::video::control::entities::unit::UnitEntity;
use crate::interface::video::control::entities::unit::SourcesParseError;
use crate::string::{LocalizedStrings, GetLocalizedStringError};
use crate::device::DeadOrAlive::Alive;
use crate::collections::Bytes;
use crate::integers::u6;
use std::iter::FusedIterator;
use serde::ser::SerializeSeq;
use serde::de::{Visitor, SeqAccess, Error};
use crate::universally_unique_identifiers_support::UniversallyUniqueIdentifier;


include!("ExtensionCodeAndControls.rs");
include!("ExtensionControls.rs");
include!("ExtensionControlsIterator.rs");
include!("ExtensionUnitEntity.rs");
include!("ExtensionUnitEntityParseError.rs");
