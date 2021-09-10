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
use crate::version::{VersionParseError, Version};
use crate::string::{GetWebUrlError, WebUrl};
use crate::device::{DeviceConnection, DeadOrAlive};
use crate::device::DeadOrAlive::Alive;
use crate::collections::Bytes;


include!("WebUsbPlatformDeviceCapability.rs");
include!("WebUsbPlatformDeviceCapabilityParseError.rs");
