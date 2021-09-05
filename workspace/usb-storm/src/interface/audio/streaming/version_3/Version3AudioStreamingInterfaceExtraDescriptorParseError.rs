// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version3AudioStreamingInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	GenericParse(GenericAudioStreamingInterfaceExtraDescriptorParseError),
	
	#[allow(missing_docs)]
	GeneralParse(GeneralParseError),
	
	#[allow(missing_docs)]
	ValidSamplingFrequencyRangeParse(ValidSamplingFrequencyRangeParseError),
}

impl Display for Version3AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version3AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version3AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			GenericParse(cause) => Some(cause),
			
			GeneralParse(cause) => Some(cause),
			
			ValidSamplingFrequencyRangeParse(cause) => Some(cause),
		}
	}
}

impl From<GenericAudioStreamingInterfaceExtraDescriptorParseError> for Version3AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: GenericAudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		Version3AudioStreamingInterfaceExtraDescriptorParseError::GenericParse(cause)
	}
}
