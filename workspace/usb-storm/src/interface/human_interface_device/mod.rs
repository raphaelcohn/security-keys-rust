// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::report::CollectionCommon;
use self::report::ReportParser;
use self::report::ReportParseError;
use crate::collections::VecExt;
use crate::collections::Bytes;
use crate::descriptors::descriptor_index;
use crate::version::Version;
use crate::version::VersionParseError;
use crate::descriptors::DescriptorParser;
use crate::descriptors::DescriptorType;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::verify_remaining_bytes;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::transmute;
use swiss_army_knife::non_zero::new_non_zero_u8;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::collections::TryReserveError;
use std::num::NonZeroU8;
use crate::device::{DeviceConnection, ReusableBuffer};
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;
use crate::interface::InterfaceNumber;


/// Report.
pub mod report;


include!("HumanInterfaceDeviceCountryCode.rs");
include!("HumanInterfaceDeviceInterfaceExtraDescriptor.rs");
include!("HumanInterfaceDeviceInterfaceExtraDescriptorParseError.rs");
include!("HumanInterfaceDeviceInterfaceExtraDescriptorParser.rs");
include!("HumanInterfaceDeviceOptionalDescriptor.rs");
include!("HumanInterfaceDeviceOptionalDescriptorType.rs");
include!("HumanInterfaceDeviceVariant.rs");
include!("OptionalDescriptorParseError.rs");
