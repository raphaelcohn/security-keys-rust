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
use std::mem::size_of;
use std::ops::Deref;
use crate::collections::WrappedIndexMap;
use crate::collections::WithCapacity;
use crate::collections::Bytes;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::num::NonZeroU8;


include!("MicrosoftOperatingSystemDescriptorSupport.rs");
include!("MicrosoftOperatingSystemPlatformDeviceCapability.rs");
include!("MicrosoftOperatingSystemPlatformDeviceCapabilityParseError.rs");
include!("MicrosoftOperatingSystemPlatformDeviceCapabilitySet.rs");
include!("MicrosoftVendorCode.rs");
include!("WindowsVersion.rs");
