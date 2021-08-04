// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Device Firmware Upgrade (DFU) descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError
{
	#[allow(missing_docs)]
	DescriptorIsNeitherOfficialOrVendorSpecific(DescriptorType),
	
	/// This type of descriptor must be at least 9 bytes long (including `bLength`).
	WrongLength
	{
		#[allow(missing_docs)]
		length: usize
	},
	
	#[allow(missing_docs)]
	ReservedAttributesBits4To7
	{
		bmAttributes: u8,
	},
	
	/// A country code of 36 or greater.
	Version(VersionParseError),
}

impl Display for DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError::*;
		
		match self
		{
			Version(cause) => Some(cause),
			
			_ => None,
		}
	}
}
