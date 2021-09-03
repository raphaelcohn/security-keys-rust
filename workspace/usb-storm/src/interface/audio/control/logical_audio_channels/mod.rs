// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::collections::WithCapacity;
use crate::collections::WrappedBitFlags;
use crate::collections::WrappedIndexSet;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::device::DeviceConnection;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::entity_index_non_constant;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::num::NonZeroU8;
use std::ops::Deref;
use enumflags2::BitFlag;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("InputLogicalAudioChannelClusters.rs");
include!("InputPinNumber.rs");
include!("LogicalAudioChannel.rs");
include!("LogicalAudioChannelCluster.rs");
include!("LogicalAudioChannelNumber.rs");
include!("LogicalAudioChannelClusterParseError.rs");
include!("LogicalAudioChannelSpatialLocation.rs");
