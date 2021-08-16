// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version1MixerUnitEntityParseError
{
	#[allow(missing_docs)]
	BLengthTooShort,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForControls(TryReserveError),
	
	#[allow(missing_docs)]
	LogicalAudioChannelClusterParse(LogicalAudioChannelClusterParseError<Infallible>),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSources(TryReserveError),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for Version1MixerUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version1MixerUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version1MixerUnitEntityParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForControls(cause) => Some(cause),
			
			LogicalAudioChannelClusterParse(cause) => Some(cause),
			
			CouldNotAllocateMemoryForSources(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<LogicalAudioChannelClusterParseError<Infallible>> for Version1MixerUnitEntityParseError
{
	#[inline(always)]
	fn from(cause: LogicalAudioChannelClusterParseError<Infallible>) -> Self
	{
		Version1MixerUnitEntityParseError::LogicalAudioChannelClusterParse(cause)
	}
}
