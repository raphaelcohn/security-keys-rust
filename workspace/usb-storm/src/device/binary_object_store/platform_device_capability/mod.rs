// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::serde::TryReserveErrorRemote;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use self::microsoft_operating_system::MicrosoftOperatingSystemPlatformDeviceCapability;
use self::microsoft_operating_system::MicrosoftOperatingSystemPlatformDeviceCapabilityParseError;
use self::web_usb::WebUsbPlatformDeviceCapability;
use self::web_usb::WebUsbPlatformDeviceCapabilityParseError;
use crate::universally_unique_identifiers_support::UniversallyUniqueIdentifier;
use crate::device::{DeviceConnection, DeadOrAlive};
use crate::device::binary_object_store::minimum_size;
use crate::collections::{Bytes, VecExt};
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::device::DeadOrAlive::Alive;


/// Microsoft operating system platform device capability.
pub mod microsoft_operating_system;


/// Web USB platform device capability.
pub mod web_usb;


include!("PlatformDeviceCapability.rs");
include!("PlatformDeviceCapabilityParseError.rs");
