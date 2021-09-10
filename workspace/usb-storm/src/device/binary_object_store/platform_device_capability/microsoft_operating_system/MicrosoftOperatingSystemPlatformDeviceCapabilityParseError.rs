// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MicrosoftOperatingSystemPlatformDeviceCapabilityParseError
{
	#[allow(missing_docs)]
	ValueBytesNotAnExactArrayMultiple
	{
		value_bytes_length: usize
	},
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForArray(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	VersionLessThanWindows81
	{
		dwWindowsVersion: u32,
	},

	#[allow(missing_docs)]
	DuplicateWindowsVersion
	{
		windows_version: WindowsVersion,
	},
}

impl Display for MicrosoftOperatingSystemPlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for MicrosoftOperatingSystemPlatformDeviceCapabilityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use MicrosoftOperatingSystemPlatformDeviceCapabilityParseError::*;
		
		match self
		{
			CanNotAllocateMemoryForArray(cause) => Some(cause),
			
			_ => None,
		}
	}
}
