// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PlatformDeviceCapabilityParseError
{
	#[allow(missing_docs)]
	TooShort,
	
	#[allow(missing_docs)]
	HasReservedByteSet,
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForValue(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	WebUsbPlatformDeviceCapabilityParse(WebUsbPlatformDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	MicrosoftOperatingSystemPlatformDeviceCapabilityParse(MicrosoftOperatingSystemPlatformDeviceCapabilityParseError),
}

impl Display for PlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for PlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use PlatformDeviceCapabilityParseError::*;
		
		match self
		{
			CanNotAllocateMemoryForValue(cause) => Some(cause),
			
			WebUsbPlatformDeviceCapabilityParse(cause) => Some(cause),
			
			MicrosoftOperatingSystemPlatformDeviceCapabilityParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<TryReserveError> for PlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: TryReserveError) -> Self
	{
		PlatformDeviceCapabilityParseError::CanNotAllocateMemoryForValue(cause)
	}
}

impl From<WebUsbPlatformDeviceCapabilityParseError> for PlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: WebUsbPlatformDeviceCapabilityParseError) -> Self
	{
		PlatformDeviceCapabilityParseError::WebUsbPlatformDeviceCapabilityParse(cause)
	}
}

impl From<MicrosoftOperatingSystemPlatformDeviceCapabilityParseError> for PlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: MicrosoftOperatingSystemPlatformDeviceCapabilityParseError) -> Self
	{
		PlatformDeviceCapabilityParseError::MicrosoftOperatingSystemPlatformDeviceCapabilityParse(cause)
	}
}
