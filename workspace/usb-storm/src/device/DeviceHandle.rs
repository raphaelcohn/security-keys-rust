// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct DeviceHandle
{
	libusb_device_handle: NonNull<libusb_device_handle>,
	
	claimed_interfaces_bit_set: u32,
}

impl Drop for DeviceHandle
{
	#[inline(always)]
	fn drop(&mut self)
	{
		self.loop_over_set_bits(|interface_number|
		{
			let _ = self.release_interface(interface_number);
		});
		
		unsafe { libusb_close(self.libusb_device_handle.as_ptr()) };
	}
}

impl DeviceHandle
{
	#[inline(always)]
	pub(crate) fn open(libusb_device: NonNull<libusb_device>) -> Result<DeadOrAlive<Self>, DeviceHandleOpenError>
	{
		use DeadOrAlive::*;
		use DeviceHandleOpenError::*;
		
		let mut libusb_device_handle = MaybeUninit::uninit();
		let result = unsafe { libusb_open(libusb_device.as_ptr(), libusb_device_handle.as_mut_ptr()) };
		if likely!(result == 0)
		{
			Ok
			(
				Alive
				(
					Self
					{
						libusb_device_handle: new_non_null(unsafe { libusb_device_handle.assume_init() }),
						
						claimed_interfaces_bit_set: 0
					}
				)
			)
		}
		else if likely!(result < 0)
		{
			match result
			{
				LIBUSB_ERROR_IO => Ok(Dead),
				
				LIBUSB_ERROR_INVALID_PARAM => unreachable!("Windows and Linux have a 4096 byte transfer limit (including setup byte)"),
				
				LIBUSB_ERROR_ACCESS => Err(AccessDenied),
				
				LIBUSB_ERROR_NO_DEVICE => Ok(Dead),
				
				LIBUSB_ERROR_NOT_FOUND => unreachable!("How"),
				
				LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
				
				LIBUSB_ERROR_TIMEOUT => Ok(Dead),
				
				LIBUSB_ERROR_OVERFLOW => Err(OutOfMemory),
				
				LIBUSB_ERROR_PIPE => unreachable!("This is not a control transfer"),
				
				// Only ever occurs in `handle_events()`
				LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
				
				LIBUSB_ERROR_NO_MEM => Err(OutOfMemory),
				
				LIBUSB_ERROR_NOT_SUPPORTED => unreachable!("Operating System driver does not support a control transfer"),
				
				-13 ..= -98 => panic!("Newly defined error code {}", result),
				
				LIBUSB_ERROR_OTHER => Err(Other),
				
				_ => unreachable!("LIBUSB_ERROR out of range: {}", result)
			}
		}
		else
		{
			unreachable!("Positive result {} from libusb_open()", result)
		}
	}
	
	#[inline(always)]
	pub(crate) const fn as_non_null(&self) -> NonNull<libusb_device_handle>
	{
		self.libusb_device_handle
	}
	
	#[inline(always)]
	pub(crate) const fn as_ptr(&self) -> *const libusb_device_handle
	{
		self.as_non_null().as_ptr()
	}
	
	/// Calls `callback` with a zero-based index of each set bit, from least significant to most significant.
	#[inline(always)]
	fn loop_over_set_bits(&self, mut callback: impl FnMut(u8))
	{
		let mut bit_set = self.claimed_interfaces_bit_set;
		while unlikely!(bit_set != 0)
		{
			let t = bit_set & bit_set.wrapping_neg();
			let set_bit_index = bit_set.trailing_zeros();
			callback(set_bit_index as u8);
			bit_set ^= t;
		}
	}
	
	#[inline(always)]
	fn release_interface(&self, interface_number: InterfaceNumber) -> Result<(), ()>
	{
		let result = unsafe { libusb_release_interface(self.libusb_device_handle.as_ptr(), interface_number as i32) };
		if likely!(result == 0)
		{
			return Ok(())
		}
		else if likely!(result < 0)
		{
			match result
			{
				LIBUSB_ERROR_IO => Err(()),
				
				LIBUSB_ERROR_INVALID_PARAM => unreachable!("Windows and Linux have a 4096 byte transfer limit (including setup byte)"),
				
				LIBUSB_ERROR_ACCESS => panic!("Access denied"),
				
				LIBUSB_ERROR_NO_DEVICE => Ok(()),
				
				LIBUSB_ERROR_NOT_FOUND => panic!("We never claimed the interface!"),
				
				LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
				
				LIBUSB_ERROR_TIMEOUT => Err(()),
				
				LIBUSB_ERROR_OVERFLOW => Err(()),
				
				LIBUSB_ERROR_PIPE => unreachable!("This is not a control transfer"),
				
				// Only ever occurs in `handle_events()`
				LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
				
				LIBUSB_ERROR_NO_MEM => Err(()),
				
				LIBUSB_ERROR_NOT_SUPPORTED => unreachable!("Operating System driver does not support a control transfer"),
				
				-13 ..= -98 => Err(()),
				
				LIBUSB_ERROR_OTHER => Err(()),
				
				_ => unreachable!("LIBUSB_ERROR out of range: {}", result)
			}
		}
		else
		{
			unreachable!("Positive result {} from libusb_release_interface()", result)
		}
	}
}
