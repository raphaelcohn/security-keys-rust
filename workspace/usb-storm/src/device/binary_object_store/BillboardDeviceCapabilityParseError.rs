// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BillboardDeviceCapabilityParseError
{
	#[allow(missing_docs)]
	ShorterThanMinimumSize,
	
	#[allow(missing_docs)]
	TooShort,
	
	#[allow(missing_docs)]
	InvalidAdditionalInformationUrl(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	PreferredAlternateModeIndexTooLarge
	{
		preferred_alternate_mode_index: u8,
		
		number_of_alternate_modes: u8,
	},
	
	#[allow(missing_docs)]
	TooManyModes
	{
		number_of_modes: u8,
	},
	
	#[allow(missing_docs)]
	VersionParse(VersionParseError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForModes(TryReserveError),
	
	#[allow(missing_docs)]
	InvalidAlternateModeDescription
	{
		cause: GetLocalizedStringError,
	
		index: usize,
	},
}

impl Display for BillboardDeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for BillboardDeviceCapabilityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use BillboardDeviceCapabilityParseError::*;
		
		match self
		{
			InvalidAdditionalInformationUrl(cause) => Some(cause),
			
			VersionParse(cause) => Some(cause),
			
			CouldNotAllocateMemoryForModes(cause) => Some(cause),
			
			InvalidAlternateModeDescription { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
