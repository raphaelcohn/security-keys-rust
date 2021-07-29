// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn control_transfer<const direction: Direction, const request_type: ControlTransferRequestType, const recipient: ControlTransferRecipient, const request: Request>(device_handle: NonNull<libusb_device_handle>, time_out: Duration, value: u16, index: u16, buffer: &mut [MaybeUninit<u8>]) -> Result<&[u8], ControlTransferError>
{
	let length = buffer.len();
	debug_assert!(length < 4096);
	
	let time_out = min(time_out.as_millis(), u32::MAX as u128) as u32;
	
	let request_type = (direction as u8) | (request_type as u8) | (recipient as u8);
	
	// Internally, calls `libusb_submit_transfer()`.
	let result = unsafe { libusb_control_transfer(device_handle.as_ptr(), request_type,request as u8, descriptor_type | (desc_index as u16), langid, data, length as u16, time_out) };
	
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
		use self::ControlTransferError::*;
		
		let error = match result
		{
			LIBUSB_ERROR_IO => TransferInputOutputErrorOrTransferCancelled,
			
			// Documented.
			LIBUSB_ERROR_INVALID_PARAM => unreachable!("Windows and Linux have a 4096 byte transfer limit (including setup byte)"),
			
			LIBUSB_ERROR_ACCESS => panic!("Access denied"),
			
			// Documented.
			LIBUSB_ERROR_NO_DEVICE => DeviceDisconnected,
			
			LIBUSB_ERROR_NOT_FOUND => unreachable!("Probably bug in libusb"),
			
			// Documented.
			LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
			
			// Documented.
			LIBUSB_ERROR_TIMEOUT => TimedOut(TimeOut),
			
			LIBUSB_ERROR_OVERFLOW => BufferOverflow,
			
			// Documented as an unsupported control request, which seems to be a mistake.
			LIBUSB_ERROR_PIPE => ControlRequestNotSupported,
			
			// Only ever occurs in `handle_events()`
			LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
			
			// could not allocate memory.
			LIBUSB_ERROR_NO_MEM => OutOfMemory,
			
			LIBUSB_ERROR_NOT_SUPPORTED => unreachable!("Operating System driver does not support a control transfer"),
			
			-13 ..= -98 => NewlyDefined(result),
			
			// Failed to arm timer (eg using `timerfd_settime()`).
			// `darwin_to_libusb()` error that library didn't know what to do with.
			LIBUSB_ERROR_OTHER => Other,
			
			_ => unreachable!("LIBUSB_ERROR out of range: {}", result)
		};
		Err(error)
	}
}
