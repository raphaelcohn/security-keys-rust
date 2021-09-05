// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version1EntityDescriptorParseError
{
	#[allow(missing_docs)]
	InputTerminalEntityParse(Version1InputTerminalEntityParseError),
	
	#[allow(missing_docs)]
	OutputTerminalEntityParse(Version1OutputTerminalEntityParseError),
	
	#[allow(missing_docs)]
	MixerUnitEntityParse(Version1MixerUnitEntityParseError),
	
	#[allow(missing_docs)]
	SelectorUnitEntityParse(Version1SelectorUnitEntityParseError),
	
	#[allow(missing_docs)]
	FeatureUnitEntityParse(Version1FeatureUnitEntityParseError),
	
	#[allow(missing_docs)]
	ProcessingUnitEntityParse(Version1ProcessingUnitEntityParseError),
	
	#[allow(missing_docs)]
	ExtensionUnitEntityParse(Version1ExtensionUnitEntityParseError),
}

impl Display for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version1EntityDescriptorParseError::*;
		
		match self
		{
			InputTerminalEntityParse(cause) => Some(cause),
			
			OutputTerminalEntityParse(cause) => Some(cause),
			
			SelectorUnitEntityParse(cause) => Some(cause),
			
			MixerUnitEntityParse(cause) => Some(cause),
			
			FeatureUnitEntityParse(cause) => Some(cause),
			
			ProcessingUnitEntityParse(cause) => Some(cause),
			
			ExtensionUnitEntityParse(cause) => Some(cause),
		}
	}
}

impl From<Version1InputTerminalEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1InputTerminalEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::InputTerminalEntityParse(cause)
	}
}

impl From<Version1OutputTerminalEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1OutputTerminalEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::OutputTerminalEntityParse(cause)
	}
}

impl From<Version1MixerUnitEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1MixerUnitEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::MixerUnitEntityParse(cause)
	}
}

impl From<Version1SelectorUnitEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1SelectorUnitEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::SelectorUnitEntityParse(cause)
	}
}

impl From<Version1FeatureUnitEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1FeatureUnitEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::FeatureUnitEntityParse(cause)
	}
}

impl From<Version1ProcessingUnitEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1ProcessingUnitEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::ProcessingUnitEntityParse(cause)
	}
}

impl From<Version1ExtensionUnitEntityParseError> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1ExtensionUnitEntityParseError) -> Self
	{
		Version1EntityDescriptorParseError::ExtensionUnitEntityParse(cause)
	}
}
