// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::EntityDescriptorParseError;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::ClockEntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use crate::VecExt;
use crate::collections::WrappedHashMap;
use crate::device::DeadOrAlive;
use crate::string::StringFinder;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::error;
use std::fmt::Debug;
use std::hash::Hash;


include!("ClockEntity.rs");
include!("Entities.rs");
include!("Entity.rs");
include!("TerminalEntity.rs");
include!("UnitEntity.rs");
