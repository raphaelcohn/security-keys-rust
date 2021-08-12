// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2EntityDescriptorParseError
{
	#[allow(missing_docs)]
	LogicalAudioChannelClusterParse(LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	SelectorClockCouldNotAllocateSources(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	InvalidControl,
	
	#[allow(missing_docs)]
	SelectorClockPIsTooLarge,
	
	#[allow(missing_docs)]
	MixerUnitBLengthTooShort,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSources(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForMixerControls(TryReserveError),
}

impl Display for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2EntityDescriptorParseError::*;
		
		match self
		{
			LogicalAudioChannelClusterParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			SelectorClockCouldNotAllocateSources(cause) => Some(cause),
			
			CouldNotAllocateMemoryForSources(cause) => Some(cause),
			
			CouldNotAllocateMemoryForMixerControls(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl Into<EntityDescriptorParseError<Version2EntityDescriptorParseError>> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn into(self) -> EntityDescriptorParseError<Self>
	{
		EntityDescriptorParseError::Version(self)
	}
}

impl From<LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>) -> Self
	{
		Version2EntityDescriptorParseError::LogicalAudioChannelClusterParse(cause)
	}
}
