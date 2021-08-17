// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::super::integers::NonZeroU7;
use libusb1_sys::libusb_device;
use libusb1_sys::libusb_get_bus_number;
use libusb1_sys::libusb_get_device_address;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::ptr::NonNull;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("AssignedAddress.rs");
include!("LogicalLocation.rs");
include!("get_bus_number.rs");
include!("get_device_address.rs");
