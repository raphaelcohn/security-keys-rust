// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_configuration(libusb_device_handle: NonNull<libusb_device_handle>) -> Result<Option<ConfigurationNumber>, ControlTransferError>
{
	let mut configuration_number: MaybeUninit<i32> = MaybeUninit::uninit();
	
	let result = unsafe { libusb_get_configuration(libusb_device_handle.as_ptr(), configuration_number.as_mut_ptr()) };
	if likely!(result == 0)
	{
		let configuration_number = unsafe { configuration_number.assume_init() };
		if unlikely!(configuration_number < 0 || configuration_number > (u8::MAX as i32))
		{
			unreachable!("configuration_number out of range: {}", configuration_number)
		}
		Ok(unsafe { transmute(configuration_number as u8) })
	}
	else
	{
		// This works because `libusb_get_configuration()` wraps a control transfer internally.
		Err(ControlTransferError::parse(result, libusb_device_handle))
	}
}
