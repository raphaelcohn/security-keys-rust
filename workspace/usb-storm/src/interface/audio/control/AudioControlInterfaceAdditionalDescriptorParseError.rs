// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioControlInterfaceAdditionalDescriptorParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	ParseVersion(VersionParseError),
	
	#[allow(missing_docs)]
	ExpectedHeaderDescriptorSubtype,
	
	#[allow(missing_docs)]
	wTotalLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	ParseEntity(EntityDescriptorParseError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUnrecognized(TryReserveError),
	
	#[allow(missing_docs)]
	Version1OrVersion2EntityDescriptorsOutOfMemory(TryReserveError),
	
	#[allow(missing_docs)]
	Version1InterfaceNumberTooBig
	{
		index: u8,
	
		interface_number: u8,
	},
	
	#[allow(missing_docs)]
	Version1InterfaceNumberDuplicated
	{
		index: u8,
	
		interface_number: InterfaceNumber,
	},
}

impl Display for AudioControlInterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for AudioControlInterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use AudioControlInterfaceAdditionalDescriptorParseError::*;
		
		match self
		{
			ParseVersion(cause) => Some(cause),
			
			ParseEntity(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUnrecognized(cause) => Some(cause),
			
			Version1OrVersion2EntityDescriptorsOutOfMemory(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<VersionParseError> for AudioControlInterfaceAdditionalDescriptorParseError
{
	fn from(cause: VersionParseError) -> Self
	{
		AudioControlInterfaceAdditionalDescriptorParseError::ParseVersion(cause)
	}
}

impl From<EntityDescriptorParseError> for AudioControlInterfaceAdditionalDescriptorParseError
{
	fn from(cause: EntityDescriptorParseError) -> Self
	{
		AudioControlInterfaceAdditionalDescriptorParseError::ParseEntity(cause)
	}
}
