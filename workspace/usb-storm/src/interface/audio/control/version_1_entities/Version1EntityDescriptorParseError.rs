// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version1EntityDescriptorParseError
{
	#[allow(missing_docs)]
	LogicalAudioChannelClusterParse(LogicalAudioChannelClusterParseError),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	MixerUnitBLengthTooShort,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSources(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForMixerControls(TryReserveError),
	
	#[allow(missing_docs)]
	SelectorUnitLengthWrong,
	
	#[allow(missing_docs)]
	FeatureUnitControlSizeIsZero,
	
	#[allow(missing_docs)]
	FeatureUnitControlsHaveRemainder,
	
	#[allow(missing_docs)]
	FeatureUnitLengthWrong,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForFeatureControls(TryReserveError),
	
	#[allow(missing_docs)]
	ProcessingUnitPIsTooLarge,
	
	#[allow(missing_docs)]
	ProcessingUnitControlSizeIsZero,
	
	#[allow(missing_docs)]
	ProcessingUnitHasTooFewBytesForControlsAndProcessSpecificData,
	
	#[allow(missing_docs)]
	ProcessingUnitHasTooFewBytesForProcessSpecificData,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForProcessTypeUndefinedData(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForProcessTypeUnrecognizedControls(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForProcessTypeUnrecognizedData(TryReserveError),
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData,
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent
	{
		mode: BitFlags<LogicalAudioChannelSpatialLocation>,
		
		spatial_location: LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeHasDuplicateMode
	{
		mode: BitFlags<LogicalAudioChannelSpatialLocation>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData,
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveMoreThanThreeModes,
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveThisMode
	{
		mode: u16
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeHasDuplicateMode
	{
		mode: DolbyProLogicMode,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent
	{
		mode: DolbyProLogicMode,
		
		spatial_location: LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	ThreeDimensionalStereoExtendedProcessTypeMustHaveLeftAndRightSpatialChannels,
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	ThreeDimensionalStereoExtendedProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	ReverberationProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	ChorusProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorProcessTypeMustHaveOnlyOneInputPin,
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
			LogicalAudioChannelClusterParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			CouldNotAllocateMemoryForSources(cause) => Some(cause),
			
			CouldNotAllocateMemoryForMixerControls(cause) => Some(cause),
			
			CouldNotAllocateMemoryForFeatureControls(cause) => Some(cause),
			
			CouldNotAllocateMemoryForProcessTypeUndefinedData(cause) => Some(cause),
			
			CouldNotAllocateMemoryForProcessTypeUnrecognizedControls(cause) => Some(cause),
			
			CouldNotAllocateMemoryForProcessTypeUnrecognizedData(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl Into<EntityDescriptorParseError<Version1EntityDescriptorParseError>> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn into(self) -> EntityDescriptorParseError<Self>
	{
		EntityDescriptorParseError::Version(self)
	}
}

impl From<LogicalAudioChannelClusterParseError<Version1EntityDescriptorParseError>> for Version1EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: LogicalAudioChannelClusterParseError) -> Self
	{
		Version1EntityDescriptorParseError::LogicalAudioChannelClusterParse(cause)
	}
}
