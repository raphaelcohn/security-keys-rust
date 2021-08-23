// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn control_transfer(device_handle: NonNull<libusb_device_handle>, direction: Direction, control_transfer_function_identifier: (ControlTransferRequestType, ControlTransferRecipient, impl Into<u8>), value: u16, index: u16, buffer: &mut [MaybeUninit<u8>]) -> Result<&[u8], ControlTransferError>
{
	let (request_type, recipient, request) = control_transfer_function_identifier;
	
	let request_type = (direction as u8) | (request_type as u8) | (recipient as u8);
	let length = buffer.len();
	let time_out =
	{
		const TimeOut: Duration = Duration::from_millis(1_000);
		min(TimeOut.as_millis(), u32::MAX as u128) as u32
	};
	
	// Internally, calls `libusb_submit_transfer()`.
	let result = unsafe { libusb_control_transfer(device_handle.as_ptr(), request_type,request.into(), value, index, buffer.as_mut_ptr() as *mut u8, length as u16, time_out) };
	
	if likely!(result >= 0)
	{
		let used_length = result as usize;
		if unlikely!(used_length > length)
		{
			unreachable!("Serious bug in libusb; libusb_control_transfer() is reporting an invalid length")
		}
		Ok(unsafe { MaybeUninit::slice_assume_init_ref(buffer.get_unchecked_range_safe(.. length)) })
	}
	else
	{
		Err(ControlTransferError::parse(result, device_handle))
	}
}
