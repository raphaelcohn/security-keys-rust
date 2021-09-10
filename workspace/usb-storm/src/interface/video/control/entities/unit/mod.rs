// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use super::Entity;
use crate::interface::video::control::entity_identifiers::UnitEntityIdentifier;
use crate::interface::video::control::entity_identifiers::EntityIdentifier;
use crate::collections::{WrappedIndexSet, Bytes, WithCapacity};
use crate::interface::video::control::entities::entity_index;
use crate::interface::video::control::entities::entity_index_non_constant;
use crate::serde::TryReserveErrorRemote;
use std::collections::TryReserveError;
use std::ops::Deref;


/// Encoding unit entity descriptors.
///
/// Only exist for specification version 1.5+.
pub mod encoding;


/// Extension unit entity descriptors.
pub mod extension;


/// Processing unit entity descriptors.
pub mod processing;


/// Selector unit entity descriptors.
pub mod selector;


include!("Sources.rs");
include!("SourcesParseError.rs");
include!("UnitEntity.rs");
include!("WithSourcesUnitEntity.rs");
