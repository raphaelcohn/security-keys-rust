// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HumanInterfaceDeviceInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	DescriptorIsNeitherOfficialOrVendorSpecific(DescriptorType),
	
	/// This type of descriptor must be at least 9 bytes long (including `bLength`).
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	/// A country code of 36 or greater.
	ReservedCountryCode(u8),
	
	/// A country code of 36 or greater.
	Version(VersionParseError),
	
	/// `bNumDescriptors` was zero.
	ZeroNumberOfClassDescriptors,
	
	/// Unrecognised report descriptor type.
	UnrecognisedReportDescriptorType(DescriptorType),
	
	#[allow(missing_docs)]
	IncorrectNumberOfOptionalDescriptors,
	
	#[allow(missing_docs)]
	ExcessBytesAfterOptionalDescriptors,
	
	#[allow(missing_docs)]
	CouldNotAllocateSpaceForOptionalDescriptors(TryReserveError),
	
	#[allow(missing_docs)]
	InvalidOptionalDescriptor
	{
		bDescriptorType: u8,
	},
}

impl Display for HumanInterfaceDeviceInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for HumanInterfaceDeviceInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use HumanInterfaceDeviceInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			Version(cause) => Some(cause),
			
			CouldNotAllocateSpaceForOptionalDescriptors(cause) => Some(cause),
			
			_ => None,
		}
	}
}
