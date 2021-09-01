// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioControlInterfaceExtraDescriptorParseError
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
	wTotalLengthExceedsRemainingBytes
	{
		expected_length: usize,
		
		wTotalLength: u16,
	},
	
	#[allow(missing_docs)]
	ParseVersion1Entity(EntityDescriptorParseError<Version1EntityDescriptorParseError>),
	
	#[allow(missing_docs)]
	ParseVersion2Entity(EntityDescriptorParseError<Version2EntityDescriptorParseError>),
	
	#[allow(missing_docs)]
	ParseVersion3Entity(EntityDescriptorParseError<Version3EntityDescriptorParseError>),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUnrecognized(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForInterfaceNumbers(TryReserveError),
	
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

impl Display for AudioControlInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for AudioControlInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use AudioControlInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			ParseVersion(cause) => Some(cause),
			
			ParseVersion1Entity(cause) => Some(cause),
			
			ParseVersion2Entity(cause) => Some(cause),
			
			ParseVersion3Entity(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUnrecognized(cause) => Some(cause),
			
			CouldNotAllocateMemoryForInterfaceNumbers(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<VersionParseError> for AudioControlInterfaceExtraDescriptorParseError
{
	fn from(cause: VersionParseError) -> Self
	{
		AudioControlInterfaceExtraDescriptorParseError::ParseVersion(cause)
	}
}

impl From<EntityDescriptorParseError<Version1EntityDescriptorParseError>> for AudioControlInterfaceExtraDescriptorParseError
{
	fn from(cause: EntityDescriptorParseError<Version1EntityDescriptorParseError>) -> Self
	{
		AudioControlInterfaceExtraDescriptorParseError::ParseVersion1Entity(cause)
	}
}

impl From<EntityDescriptorParseError<Version2EntityDescriptorParseError>> for AudioControlInterfaceExtraDescriptorParseError
{
	fn from(cause: EntityDescriptorParseError<Version2EntityDescriptorParseError>) -> Self
	{
		AudioControlInterfaceExtraDescriptorParseError::ParseVersion2Entity(cause)
	}
}

impl From<EntityDescriptorParseError<Version3EntityDescriptorParseError>> for AudioControlInterfaceExtraDescriptorParseError
{
	fn from(cause: EntityDescriptorParseError<Version3EntityDescriptorParseError>) -> Self
	{
		AudioControlInterfaceExtraDescriptorParseError::ParseVersion3Entity(cause)
	}
}
