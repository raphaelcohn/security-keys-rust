// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use std::borrow::Borrow;
use std::sync::Arc;
use self::c::constants::MAX_DEVICENAME;
use self::c::types::DWORD;
use self::driver::Driver;
use self::usb::UsbDeviceName;


mod c;


/// Driver.
pub mod driver;


/// Errors.
pub mod errors;


/// USB.
pub mod usb;


include!("Context.rs");
include!("LogicalUnitNumber.rs");
