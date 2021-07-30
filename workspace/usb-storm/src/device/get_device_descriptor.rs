// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_device_descriptor(libusb_device: NonNull<libusb_device>) -> libusb_device_descriptor
{
	let mut descriptor = MaybeUninit::uninit();
	
	let result = unsafe { libusb_get_device_descriptor(libusb_device.as_ptr(), descriptor.as_mut_ptr()) };
	if likely!(result == 0)
	{
		return unsafe { descriptor.assume_init() }
	}
	unreachable!("Since libusb-1.0.16, libusb_get_device_descriptor() should never fail, but it has with {}", result)
}
