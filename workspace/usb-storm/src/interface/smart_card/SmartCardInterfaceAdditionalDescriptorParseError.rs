// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SmartCardInterfaceAdditionalDescriptorParseError
{
	#[allow(missing_docs)]
	DescriptorIsNeitherOfficialOrVendorSpecific(DescriptorType),
	
	/// This type of descriptor must be 54 bytes long (including `bLength`).
	WrongLength,
	
	/// Features are invalid.
	Features(FeaturesParseError),
}

impl Display for SmartCardInterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SmartCardInterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SmartCardInterfaceAdditionalDescriptorParseError::*;
		
		match self
		{
			Features(cause) => Some(cause),
			
			_ => None,
		}
	}
}
