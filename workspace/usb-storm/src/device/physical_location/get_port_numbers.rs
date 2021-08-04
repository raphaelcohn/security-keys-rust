// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_port_numbers(libusb_device: NonNull<libusb_device>) -> ArrayVec<PortNumber, MaximumDevicePortNumbers>
{
	let mut port_numbers  = ArrayVec::new_const();
	let result = unsafe { libusb_get_port_numbers(libusb_device.as_ptr(), port_numbers.as_mut_ptr(), MaximumDevicePortNumbers as _) };
	if likely!(result >= 0)
	{
		let count = result as usize;
		unsafe { port_numbers.set_len(count) };
	}
	else if likely!(result == LIBUSB_ERROR_OVERFLOW)
	{
		unreachable!("USB violates specification with more than 7 ports")
	}
	else
	{
		unreachable!("Undocumented error code from libusb_get_port_numbers(), {}", result)
	}
	port_numbers
}
