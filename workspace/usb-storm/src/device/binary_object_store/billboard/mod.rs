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
use crate::string::{LocalizedStrings, GetLocalizedStringError};
use crate::device::{DeviceConnection, DeadOrAlive};
use crate::collections::{VecExt, Bytes};
use crate::device::DeadOrAlive::Alive;
use crate::device::binary_object_store::{capability_descriptor_index, DeviceCapability, minimum_size};
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::mem::transmute;
use crate::version::{Version, VersionParseError};
use std::collections::TryReserveError;
use crate::serde::TryReserveErrorRemote;


include!("BillboardAlternateMode.rs");
include!("BillboardAlternateModeConfigurationResult.rs");
include!("BillboardAlternateModeDeviceCapability.rs");
include!("BillboardAlternateModeDeviceCapabilityParseError.rs");
include!("BillboardDeviceCapability.rs");
include!("BillboardDeviceCapabilityParseError.rs");
include!("BillboardDeviceContainerFailedBecause.rs");
include!("BillboardVconnPowerInWatts.rs");
