// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum AudioStreamingInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	Version1Parse(Version1AudioStreamingInterfaceExtraDescriptorParseError),
	
	#[allow(missing_docs)]
	Version2Parse(Version2AudioStreamingInterfaceExtraDescriptorParseError),
	
	#[allow(missing_docs)]
	Version3Parse(Version3AudioStreamingInterfaceExtraDescriptorParseError),
	
	#[allow(missing_docs)]
	UnrecognizedParse(UnrecognizedAudioStreamingInterfaceExtraDescriptorParseError),
}

impl Display for AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			Version1Parse(cause) => Some(cause),
			
			Version2Parse(cause) => Some(cause),
			
			Version3Parse(cause) => Some(cause),
			
			UnrecognizedParse(cause) => Some(cause),
		}
	}
}

impl From<Version1AudioStreamingInterfaceExtraDescriptorParseError> for AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version1AudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		AudioStreamingInterfaceExtraDescriptorParseError::Version1Parse(cause)
	}
}

impl From<Version2AudioStreamingInterfaceExtraDescriptorParseError> for AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2AudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		AudioStreamingInterfaceExtraDescriptorParseError::Version2Parse(cause)
	}
}

impl From<Version3AudioStreamingInterfaceExtraDescriptorParseError> for AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version3AudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		AudioStreamingInterfaceExtraDescriptorParseError::Version3Parse(cause)
	}
}

impl From<UnrecognizedAudioStreamingInterfaceExtraDescriptorParseError> for AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: UnrecognizedAudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		AudioStreamingInterfaceExtraDescriptorParseError::UnrecognizedParse(cause)
	}
}
