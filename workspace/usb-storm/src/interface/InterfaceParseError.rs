// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Interface descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InterfaceParseError
{
	/// Bug in libusb.
	NullAlternateSettingsPointer
	{
		#[allow(missing_docs)]
		interface_index: u8,
	},
	
	/// Bug in libusb.
	NegativeNumberOfAlternateSettings
	{
		#[allow(missing_docs)]
		interface_index: u8,
	},
	
	/// Bug in libusb.
	NoAlternateSettings
	{
		#[allow(missing_docs)]
		interface_index: u8,
	},
	
	/// This may actually be possible as a bug in libusb.
	///
	/// libusb only checks for u32::MAX for an alternate setting number, yet an alternate setting number can not exceed u8::MAX.
	TooManyAlternateSettings
	{
		#[allow(missing_docs)]
		interface_index: u8,
	},
	
	#[allow(missing_docs)]
	AlternateSetting(AlternateSettingParseError),
	
	#[allow(missing_docs)]
	AlternateSettingHasDifferentIndexNumber
	{
		interface_index: u8,
		
		interface_number: InterfaceNumber,
		
		parsed_interface_number: InterfaceNumber,
		
		alternate_setting_index: NonZeroU8,
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForAlternateSettings(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for InterfaceParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for InterfaceParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use InterfaceParseError::*;
		
		match self
		{
			AlternateSetting(cause) => Some(cause),
			
			CouldNotAllocateMemoryForAlternateSettings(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<AlternateSettingParseError> for InterfaceParseError
{
	#[inline(always)]
	fn from(cause: AlternateSettingParseError) -> Self
	{
		InterfaceParseError::AlternateSetting(cause)
	}
}
