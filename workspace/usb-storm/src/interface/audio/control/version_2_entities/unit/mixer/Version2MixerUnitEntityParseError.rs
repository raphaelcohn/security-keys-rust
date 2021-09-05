// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2MixerUnitEntityParseError
{
	#[allow(missing_docs)]
	BLengthTooShort,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSources(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForControlsBitMap(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ClusterControlInvalid,
	
	#[allow(missing_docs)]
	UnderflowControlInvalid,
	
	#[allow(missing_docs)]
	OverflowControlInvalid,
	
	#[allow(missing_docs)]
	LogicalAudioChannelClusterParse(LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for Version2MixerUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2MixerUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2MixerUnitEntityParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForSources(cause) => Some(cause),
			
			CouldNotAllocateMemoryForControlsBitMap(cause) => Some(cause),
			
			LogicalAudioChannelClusterParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}
