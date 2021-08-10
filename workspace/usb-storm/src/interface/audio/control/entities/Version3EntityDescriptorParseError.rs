// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityDescriptorParseError
{
	#[allow(missing_docs)]
	LessThanFourByteHeader,
	
	#[allow(missing_docs)]
	ExpectedInterfaceDescriptorType,
	
	#[allow(missing_docs)]
	UndefinedInterfaceDescriptorType,
	
	#[allow(missing_docs)]
	HeaderInterfaceDescriptorTypeAfterHeader,
	
	#[allow(missing_docs)]
	ExtendedTerminalIsAHighCapacityDescriptor,
	
	#[allow(missing_docs)]
	ConnectorsIsAHighCapacityDescriptor,
	
	#[allow(missing_docs)]
	UnrecognizedEntityDescriptorType,
	
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	OutOfMemoryPushingAnonymousEntityDescriptor(TryReserveError),
	
	#[allow(missing_docs)]
	DuplicateEntityDescriptor,
	
	#[allow(missing_docs)]
	TerminalTypeParse(TerminalTypeParseError),
	
	#[allow(missing_docs)]
	AudioDynamicStringDescriptorIdentifierIsOutOfRange,
}

impl Display for EntityDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for EntityDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use EntityDescriptorParseError::*;
		
		match self
		{
			OutOfMemoryPushingAnonymousEntityDescriptor(cause) => Some(cause),
			
			TerminalTypeParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<TerminalTypeParseError> for EntityDescriptorParseError
{
	fn from(cause: TerminalTypeParseError) -> Self
	{
		EntityDescriptorParseError::TerminalTypeParse(cause)
	}
}
