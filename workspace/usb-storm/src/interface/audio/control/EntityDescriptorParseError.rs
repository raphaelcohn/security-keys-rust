// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum EntityDescriptorParseError<E: error::Error>
{
	#[allow(missing_docs)]
	LessThanFourByteHeader,
	
	#[allow(missing_docs)]
	ExpectedInterfaceDescriptorType,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	OutOfMemoryCheckingUniqueIdentifiedEntityDescriptor(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	NonUniqueEntityIdentifier
	{
		entity_identifier: EntityIdentifier,
	},
	
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	UndefinedInterfaceDescriptorType,
	
	#[allow(missing_docs)]
	HeaderInterfaceDescriptorTypeAfterHeader,
	
	#[allow(missing_docs)]
	UnrecognizedEntityDescriptorType,
	
	#[allow(missing_docs)]
	OutOfMemoryPushingAnonymousEntityDescriptor(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	OutOfMemoryPushingIdentifiedEntityDescriptor(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	Version(E),
	
	#[allow(missing_docs)]
	DuplicateEntityIdentifier
	{
		entity_identifier: EntityIdentifier
	},
}

impl<E: error::Error> Display for EntityDescriptorParseError<E>
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl<E: 'static + error::Error> error::Error for EntityDescriptorParseError<E>
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use EntityDescriptorParseError::*;
		
		match self
		{
			OutOfMemoryCheckingUniqueIdentifiedEntityDescriptor(cause) => Some(cause),
			
			OutOfMemoryPushingAnonymousEntityDescriptor(cause) => Some(cause),
			
			OutOfMemoryPushingIdentifiedEntityDescriptor(cause) => Some(cause),
			
			Version(cause) => Some(cause),
			
			_ => None,
		}
	}
}
