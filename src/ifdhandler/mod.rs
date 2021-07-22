// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use likely::unlikely;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::sync::Arc;
use self::c::constants::MAX_DEVICENAME;
use self::c::types::DWORD;
use self::driver::Driver;
use self::usb::UsbDeviceName;
use swiss_army_knife::strings::parse_number::ParseNumberError;
use arrayvec::ArrayVec;


mod c;


pub mod driver;


pub mod errors;


pub mod usb;


include!("Context.rs");
include!("LogicalUnitNumber.rs");





struct Device
{
	
	
	/// `TAG_IFD_SLOT_THREAD_SAFE`.
	/// Always false for ifd-ccid driver.
	///
	/// Should be a property of the CcidClassDriver, but not possible to obtain it with the current design of PC/SC.
	supports_simultaneous_access_to_slots: bool,
	
	/// The `.len()` of this array should be from `TAG_IFD_SLOTS_NUMBER`.
	card_slots: Vec<Context>,
}

struct Devices
{
	devices: [Option<Device>; 16],
}

impl Devices
{
	fn assign_new_device(&mut self)
	{
	}
	
	// these will always vary... unless we allow for missing
	fn context(device_index: u16, zero_based_card_slot_index: u16)
	{
	
	}
	
	fn logical_unit_number(device_index: u16, zero_based_card_slot_index: u16) -> LogicalUnitNumber
	{
		LogicalUnitNumber
		{
			device_index,
		
			zero_based_card_slot,
		}
	}
}
