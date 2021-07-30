// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A load error.
#[derive(Debug)]
pub(crate) enum LoadError
{
	#[allow(missing_docs)]
	LoadDriver(LoadDriverError),
	
	#[allow(missing_docs)]
	FindingUsbDevices(UsbError),
	
	#[allow(missing_docs)]
	InvalidCcidInterface(UsbDeviceError),
}

impl Display for LoadError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for LoadError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use LoadError::*;
		
		match self
		{
			LoadDriver(cause) => Some(cause),
			
			FindingUsbDevices(cause) => Some(cause),
			
			InvalidCcidInterface(cause) => Some(cause),
		}
	}
}

impl From<LoadDriverError> for LoadError
{
	#[inline(always)]
	fn from(cause: LoadDriverError) -> Self
	{
		LoadError::LoadDriver(cause)
	}
}

impl From<UsbDeviceError> for LoadError
{
	#[inline(always)]
	fn from(cause: UsbDeviceError) -> Self
	{
		LoadError::InvalidCcidInterface(cause)
	}
}
