// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::WithCapacity;
use crate::collections::WrappedBitFlags;
use crate::collections::WrappedHashMap;
use crate::collections::WrappedIndexMap;
use crate::collections::WrappedIndexSet;
use crate::device::binary_object_store::minimum_size;
use crate::integers::u11;
use crate::integers::u1;
use crate::integers::u2;
use crate::integers::u4;
use crate::serde::TryReserveErrorRemote;
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
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("BitRate.rs");
include!("ReceiveOrTransmit.rs");
include!("SublinkProtocol.rs");
include!("SublinkSpeedAttribute.rs");
include!("SublinkSpeedAttributeIdentifier.rs");
include!("SublinkSpeedLinks.rs");
include!("SublinkType.rs");
include!("SublinkTypeSymmetry.rs");
include!("SuperSpeedDeviceCapability.rs");
include!("SuperSpeedDeviceCapabilityParseError.rs");
include!("SuperSpeedDeviceCapabilitySupportedSpeed.rs");
include!("SuperSpeedPlusDeviceCapability.rs");
include!("SuperSpeedPlusDeviceCapabilityParseError.rs");
