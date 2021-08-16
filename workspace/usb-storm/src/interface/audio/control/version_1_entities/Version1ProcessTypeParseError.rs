// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version1ProcessTypeParseError
{
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
		mode: WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>,
		
		spatial_location: Version1LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeHasDuplicateMode
	{
		mode: WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData,
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveThisMode(DolbyProLogicModeConversionError),
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeHasDuplicateMode
	{
		mode: WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent
	{
		mode: WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>,
		
		spatial_location: Version1LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	ThreeDimensionalStereoExtendedProcessTypeMustNotHaveProcessTypeSpecificBytes,
	
	#[allow(missing_docs)]
	ThreeDimensionalStereoExtendedProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	ReverberationProcessTypeMustNotHaveProcessTypeSpecificBytes,
	
	#[allow(missing_docs)]
	ReverberationProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	ChorusProcessTypeMustNotHaveProcessTypeSpecificBytes,
	
	#[allow(missing_docs)]
	ChorusProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorProcessTypeMustNotHaveProcessTypeSpecificBytes,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUpDownMixProcessTypeModes(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForDolbyProLogicProcessTypeModes(TryReserveError),
}

impl Display for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version1ProcessTypeParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForProcessTypeUndefinedData(cause) => Some(cause),
			
			CouldNotAllocateMemoryForProcessTypeUnrecognizedControls(cause) => Some(cause),
			
			CouldNotAllocateMemoryForProcessTypeUnrecognizedData(cause) => Some(cause),
			
			DolbyProLogicProcessTypeCanNotHaveThisMode(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUpDownMixProcessTypeModes(cause) => Some(cause),
			
			CouldNotAllocateMemoryForDolbyProLogicProcessTypeModes(cause) => Some(cause),
			
			_ => None,
		}
	}
}
