// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::{WrappedBitFlags, Bytes, VecExt};
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::interface::audio::control::ChannelControlsByChannelNumber;
use crate::interface::audio::control::entities::Entity;
use crate::interface::audio::control::entities::UnitEntity;
use crate::interface::audio::control::entity_identifiers::EntityIdentifier;
use crate::interface::audio::control::entity_identifiers::UnitEntityIdentifier;
use crate::interface::audio::control::entity_identifiers::UnitOrTerminalEntityIdentifier;
use crate::interface::audio::control::entity_index;
use crate::interface::audio::control::version_1_entities::Version1EntityDescriptorParseError;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::StringFinder;
use enumflags2::bitflags;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::size_of;
use std::mem::transmute;
use std::num::NonZeroUsize;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_usize;


include!("Version1FeatureUnitEntity.rs");
include!("Version1FeatureUnitEntityParseError.rs");
include!("Version1AudioChannelFeatureControl.rs");
