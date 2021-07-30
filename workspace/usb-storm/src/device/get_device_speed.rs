// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_device_speed(libusb_device: NonNull<libusb_device>) -> Option<Speed>
{
	use Speed::*;
	
	const LIBUSB_SPEED_SUPER_PLUS: i32 = 5;
	
	match unsafe { libusb_get_device_speed(libusb_device.as_ptr()()) }
	{
		LIBUSB_SPEED_UNKNOWN => None,
		
		LIBUSB_SPEED_LOW => Some(Low),
		
		LIBUSB_SPEED_FULL => Some(Full),
		
		LIBUSB_SPEED_HIGH => Some(High),
		
		LIBUSB_SPEED_SUPER => Some(Super),
		
		LIBUSB_SPEED_SUPER_PLUS => Some(SuperPlus),
		
		undocumented @ _ => unreachable!("Undocumented Speed {}", undocumented),
	}
}
