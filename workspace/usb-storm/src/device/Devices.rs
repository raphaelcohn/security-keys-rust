// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A list of devices.
#[derive(Debug)]
pub struct Devices
{
	context: Context,
	
	list: NonNull<NonNull<libusb_device>>,
	
	length: usize,
}

impl Drop for Devices
{
	#[inline(always)]
	fn drop(&mut self)
	{
		unsafe { libusb_free_device_list(self.list.as_ptr() as *const *mut libusb_device, true as i32) }
	}
}

impl Deref for Devices
{
	type Target = [DeviceReference];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		unsafe { from_raw_parts(transmute(self.list.as_ptr()), self.length) }
	}
}

impl Devices
{
	/// Find all attached USB devices.
	#[inline(always)]
	pub fn list(context: Context) -> Result<Self, ListDevicesError>
	{
		use ListDevicesError::*;
		
		let mut list = MaybeUninit::uninit();
		let result = unsafe { libusb_get_device_list(context.as_ptr(), list.as_mut_ptr()) };
		if likely!(result >= 0)
		{
			Ok
			(
				Self
				{
					context,
					
					list: new_non_null(unsafe { list.assume_init() as *mut NonNull<libusb_device> }),
					
					length: result as usize,
				}
			)
		}
		else if likely!(result < (i32::MAX as isize))
		{
			let error = match result as i32
			{
				LIBUSB_ERROR_IO => Unlistable,
				
				LIBUSB_ERROR_INVALID_PARAM => unreachable!("Windows and Linux have a 4096 byte transfer limit (including setup byte)"),
				
				LIBUSB_ERROR_ACCESS => AccessDenied,
				
				LIBUSB_ERROR_NO_DEVICE => Unlistable,
				
				LIBUSB_ERROR_NOT_FOUND => Unlistable,
				
				LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
				
				LIBUSB_ERROR_TIMEOUT => Unlistable,
				
				LIBUSB_ERROR_OVERFLOW => OutOfMemory,
				
				LIBUSB_ERROR_PIPE => unreachable!("Should not have caused a stall"),
				
				// Only ever occurs in `handle_events()`
				LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
				
				// could not allocate memory.
				LIBUSB_ERROR_NO_MEM => OutOfMemory,
				
				LIBUSB_ERROR_NOT_SUPPORTED => unreachable!("Operating System driver does not support a control transfer"),
				
				-98 ..= -13 => panic!("Newly defined error code {}", result),
				
				// Failed to arm timer (eg using `timerfd_settime()`).
				// `darwin_to_libusb()` error that library didn't know what to do with.
				LIBUSB_ERROR_OTHER => Other,
				
				_ => unreachable!("LIBUSB_ERROR out of range: {}", result)
			};
			Err(error)
		}
		else
		{
			unreachable!("Too negative (larger than i32): {}", result)
		}
	}
	
	/// Parse the list, removing any devices which are dead.
	#[inline(always)]
	pub fn parse(&self, buffer: &mut BinaryObjectStoreBuffer) -> Result<Vec<Device>, DeviceParseError>
	{
		let device_references = self.deref();
		let mut devices = Vec::new_with_capacity(device_references.len()).map_err(DeviceParseError::CouldNotAllocateMemoryForDevices)?;
		for device_reference in device_references
		{
			if let Alive(device) = device_reference.parse(buffer)?
			{
				devices.push(device);
			}
		}
		devices.shrink_to_fit();
		Ok(devices)
	}
}
