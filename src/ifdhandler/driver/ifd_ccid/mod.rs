// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use super::FixedDriverCapabilities;
use super::OurDriverName;
use super::super::usb::FixedUsbDeviceCapabilities;
use super::super::usb::UsbDeviceInformationDatabase;
use likely::unlikely;
use maplit::hashmap;
use plist::Dictionary;
use plist::Value;
use std::env::var_os;
use std::mem::size_of;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;
use swiss_army_knife::non_zero::new_non_zero_usize;
use swiss_army_knife::strings::parse_number::ParseNumber;


include!("entry.rs");
include!("fixed_driver_capabilities_ifd_ccid.rs");
include!("our_driver_name_ifd_ccid.rs");
include!("validate_info_plist_ifd_ccid.rs");
