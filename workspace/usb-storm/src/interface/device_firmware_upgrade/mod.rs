// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::descriptors::adjust_descriptor_index;
use crate::version::Version;
use crate::version::VersionParseError;
use crate::descriptors::DescriptorParser;
use crate::descriptors::DescriptorType;
use crate::descriptors::reduce_b_length_to_descriptor_body_length;
use crate::descriptors::verify_remaining_bytes;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::size_of;
use crate::string::StringFinder;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::Alive;


include!("DeviceFirmwareUpgradeInterfaceExtraDescriptor.rs");
include!("DeviceFirmwareUpgradeInterfaceExtraDescriptorParser.rs");
include!("DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError.rs");
