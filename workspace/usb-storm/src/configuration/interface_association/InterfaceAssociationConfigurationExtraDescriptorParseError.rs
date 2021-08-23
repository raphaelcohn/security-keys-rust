// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Interface Association descriptor (IAD) parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceAssociationConfigurationExtraDescriptorParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	InterfaceNumberTooLarge
	{
		bFirstInterface: u8,
	},
	
	#[allow(missing_docs)]
	InterfaceCountTooLarge
	{
		bInterfaceCount: u8,
	},
	
	#[allow(missing_docs)]
	LastExclusiveInterfaceNumberOutOfRange
	{
		first_inclusive_contiguous_interface_number: InterfaceNumber,
		
		bInterfaceCount: u8,
	},
	
	#[allow(missing_docs)]
	FunctionClassParse(FunctionClassParseError),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for InterfaceAssociationConfigurationExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for InterfaceAssociationConfigurationExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use InterfaceAssociationConfigurationExtraDescriptorParseError::*;
		
		match self
		{
			FunctionClassParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}
