// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An libusb backend errored whilst getting a configuration descriptor.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GetConfigurationDescriptorBackendError
{
	/// Failed to allocate heap memory.
	///
	/// `LIBUSB_ERROR_NO_MEM`.
	OutOfMemory,
	
	/// An unanticipated (undocumented) error code.
	Unanticipated(i32),
}

impl Display for GetConfigurationDescriptorBackendError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetConfigurationDescriptorBackendError
{
}

impl GetConfigurationDescriptorBackendError
{
	#[inline(always)]
	fn parse(result: i32, config_descriptor: MaybeUninit<*const libusb_config_descriptor>) -> Result<DeadOrAlive<Option<ConfigurationDescriptor>>, GetConfigurationDescriptorBackendError>
	{
		use DeadOrAlive::*;
		
		if likely!(result == 0)
		{
			let pointer = unsafe { config_descriptor.assume_init() };
			Ok(Alive(Some(ConfigurationDescriptor(new_non_null(pointer as *mut _)))))
		}
		else if likely!(result < 0)
		{
			use GetConfigurationDescriptorBackendError::*;
			
			match result
			{
				LIBUSB_ERROR_IO => Err(Unanticipated(LIBUSB_ERROR_IO)),
				
				LIBUSB_ERROR_INVALID_PARAM => Err(Unanticipated(LIBUSB_ERROR_INVALID_PARAM)),
				
				LIBUSB_ERROR_ACCESS => panic!("Access denied"),
				
				LIBUSB_ERROR_NO_DEVICE => Ok(Dead),
				
				LIBUSB_ERROR_NOT_FOUND => Ok(Alive(None)),
				
				LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
				
				LIBUSB_ERROR_TIMEOUT => Err(Unanticipated(LIBUSB_ERROR_TIMEOUT)),
				
				LIBUSB_ERROR_OVERFLOW => Err(Unanticipated(LIBUSB_ERROR_OVERFLOW)),
				
				// Documented as an unsupported control request, which seems to be a mistake.
				LIBUSB_ERROR_PIPE => Err(Unanticipated(LIBUSB_ERROR_PIPE)),
				
				// Only ever occurs in `handle_events()`
				LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
				
				// could not allocate memory.
				LIBUSB_ERROR_NO_MEM => Err(OutOfMemory),
				
				LIBUSB_ERROR_NOT_SUPPORTED => unreachable!("Operating System driver does not support get configuration"),
				
				-98 ..= -13 => panic!("Newly defined error code {}", result),
				
				LIBUSB_ERROR_OTHER => Err(Unanticipated(LIBUSB_ERROR_OTHER)),
				
				_ => unreachable!("LIBUSB_ERROR out of range: {}", result),
			}
		}
		else
		{
			unreachable!("Positive result")
		}
	}
}
