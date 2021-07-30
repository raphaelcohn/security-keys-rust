// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A control transfer error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum ControlTransferError
{
	/// `LIBUSB_ERROR_IO`.
	TransferInputOutputErrorOrTransferCancelled,
	
	/// `LIBUSB_ERROR_NO_DEVICE`.
	DeviceDisconnected,
	
	/// eg occurs with an operation like `HID_GET_REPORT`.
	/// Does not occur with `GET_DESCRIPTOR`.
	RequestedResourceNotFound,
	
	/// `LIBUSB_ERROR_TIMEOUT`.
	TimedOut(Duration),
	
	/// `LIBUSB_ERROR_OVERFLOW`.
	BufferOverflow,
	
	/// `LIBUSB_ERROR_PIPE`.
	///
	/// Internally, this is an USB `STALL`.
	///
	/// The stall will have been cleared.
	ControlRequestNotSupported
	{
		/// Result of clearing the halt.
		clear_halt_result_code: i32,
	},
	
	/// Failed to allocate heap memory.
	///
	/// `LIBUSB_ERROR_NO_MEM`.
	OutOfMemory,
	
	/// `LIBUSB_ERROR_OTHER`.
	Other,
}

impl Display for ControlTransferError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ControlTransferError
{
}

impl ControlTransferError
{
	#[inline(always)]
	pub(crate) fn parse(result: i32, device_handle: NonNull<libusb_device_handle>) -> Self
	{
		debug_assert!(result < 0);
		
		use ControlTransferError::*;
		
		match result
		{
			LIBUSB_ERROR_IO => TransferInputOutputErrorOrTransferCancelled,
			
			// Documented.
			LIBUSB_ERROR_INVALID_PARAM => unreachable!("Windows and Linux have a 4096 byte transfer limit (including setup byte)"),
			
			LIBUSB_ERROR_ACCESS => panic!("Access denied"),
			
			// Documented.
			LIBUSB_ERROR_NO_DEVICE => DeviceDisconnected,
			
			LIBUSB_ERROR_NOT_FOUND => RequestedResourceNotFound,
			
			// Documented.
			LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
			
			// Documented.
			LIBUSB_ERROR_TIMEOUT => TimedOut(TimeOut),
			
			LIBUSB_ERROR_OVERFLOW => BufferOverflow,
			
			// Documented as an unsupported control request.
			LIBUSB_ERROR_PIPE =>
			{
				let clear_halt_result_code = unsafe { libusb_clear_halt(device_handle.as_ptr(), 0) };
				ControlRequestNotSupported { clear_halt_result_code }
			},
			
			// Only ever occurs in `handle_events()`
			LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
			
			// could not allocate memory.
			LIBUSB_ERROR_NO_MEM => OutOfMemory,
			
			LIBUSB_ERROR_NOT_SUPPORTED => unreachable!("Operating System driver does not support a control transfer"),
			
			-13 ..= -98 => panic!("Newly defined error code {}", result),
			
			// Failed to arm timer (eg using `timerfd_settime()`).
			// `darwin_to_libusb()` error that library didn't know what to do with.
			LIBUSB_ERROR_OTHER => Other,
			
			_ => unreachable!("LIBUSB_ERROR out of range: {}", result)
		}
	}
}
