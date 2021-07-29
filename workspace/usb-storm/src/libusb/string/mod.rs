// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use libusb1_sys::libusb_device_handle;
use libusb1_sys::libusb_control_transfer;
use std::ptr::NonNull;

use libusb1_sys::constants::LIBUSB_DT_STRING;

use crate::control_transfers::get_descriptor;
use crate::control_transfers::GetDescriptorError;
use std::cmp::min;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::time::Duration;
use std::mem::MaybeUninit;
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("GetStringDescriptorError.rs");


/// Implentation of the statically inlined C method `libusb_get_string_descriptor()`.
pub fn get_string_descriptor(device_handle: NonNull<libusb_device_handle>, string_descriptor_index: u8, language_identifier: u16) -> Result<(), GetStringDescriptorError>
{
	let mut buffer: [MaybeUninit<u8>; MaximumUsbDescriptorLength] = MaybeUninit::uninit_array();
	let (descriptor_type, body) = get_descriptor::<LIBUSB_DT_STRING>(device_handle, string_descriptor_index, language_identifier, &mut buffer)?;
	
	if descriptor_type != LIBUSB_DT_STRING
	{
		Err()
	}
	
	
	
	if len < 2 || buf[0] != len as u8 || len & 0x01 != 0 {
		return Err(Error::BadDescriptor);
	}
	
	if len == 2 {
		return Ok(String::new());
	}
	
	let utf16: Vec<u16> = buf[..len]
		.chunks(2)
		.skip(1)
		.map(|chunk| u16::from(chunk[0]) | u16::from(chunk[1]) << 8)
		.collect();
	
	String::from_utf16(&utf16).map_err(|_| Error::Other)
}
