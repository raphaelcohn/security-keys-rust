// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum EntityDescriptorParseError
{
	#[allow(missing_docs)]
	CommonParse(CommonEntityDescriptorParseError),
	
	#[allow(missing_docs)]
	UndefinedInterfaceDescriptorType,
	
	#[allow(missing_docs)]
	HeaderInterfaceDescriptorTypeAfterHeader,
	
	#[allow(missing_docs)]
	UnrecognizedEntityDescriptorType
	{
		bDescriptorSubType: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	OutOfMemoryPushingAnonymousEntityDescriptor(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	OutOfMemoryPushingIdentifiedEntityDescriptor(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	DuplicateEntityIdentifier
	{
		entity_identifier: EntityIdentifier
	},
	
	#[allow(missing_docs)]
	InputTerminalEntityParse(InputTerminalEntityParseError),
	
	#[allow(missing_docs)]
	OutputTerminalEntityParse(OutputTerminalEntityParseError),
	
	#[allow(missing_docs)]
	EncodingUnitEntityParse(EncodingUnitEntityParseError),
	
	#[allow(missing_docs)]
	ExtensionUnitEntityParse(ExtensionUnitEntityParseError),
	
	#[allow(missing_docs)]
	ProcessingUnitEntityParse(ProcessingUnitEntityParseError),
	
	#[allow(missing_docs)]
	SelectorUnitEntityParse(SelectorUnitEntityParseError),
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
			CommonParse(cause) => Some(cause),
			
			OutOfMemoryPushingAnonymousEntityDescriptor(cause) => Some(cause),
			
			OutOfMemoryPushingIdentifiedEntityDescriptor(cause) => Some(cause),
			
			InputTerminalEntityParse(cause) => Some(cause),
			
			OutputTerminalEntityParse(cause) => Some(cause),
			
			EncodingUnitEntityParse(cause) => Some(cause),
			
			ExtensionUnitEntityParse(cause) => Some(cause),
			
			ProcessingUnitEntityParse(cause) => Some(cause),
			
			SelectorUnitEntityParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<CommonEntityDescriptorParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: CommonEntityDescriptorParseError) -> Self
	{
		EntityDescriptorParseError::CommonParse(cause)
	}
}

impl From<InputTerminalEntityParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: InputTerminalEntityParseError) -> Self
	{
		EntityDescriptorParseError::InputTerminalEntityParse(cause)
	}
}

impl From<OutputTerminalEntityParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: OutputTerminalEntityParseError) -> Self
	{
		EntityDescriptorParseError::OutputTerminalEntityParse(cause)
	}
}

impl From<EncodingUnitEntityParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: EncodingUnitEntityParseError) -> Self
	{
		EntityDescriptorParseError::EncodingUnitEntityParse(cause)
	}
}

impl From<ExtensionUnitEntityParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: ExtensionUnitEntityParseError) -> Self
	{
		EntityDescriptorParseError::ExtensionUnitEntityParse(cause)
	}
}

impl From<ProcessingUnitEntityParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: ProcessingUnitEntityParseError) -> Self
	{
		EntityDescriptorParseError::ProcessingUnitEntityParse(cause)
	}
}

impl From<SelectorUnitEntityParseError> for EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SelectorUnitEntityParseError) -> Self
	{
		EntityDescriptorParseError::SelectorUnitEntityParse(cause)
	}
}
