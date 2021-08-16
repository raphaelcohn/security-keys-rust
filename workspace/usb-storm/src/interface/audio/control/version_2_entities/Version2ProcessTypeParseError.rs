// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2ProcessTypeParseError
{
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForProcessTypeUndefinedData(TryReserveError),
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData,
	
	#[allow(missing_docs)]
	UpDownMixProceesingUnitModeSelectControlInvalid,
	
	#[allow(missing_docs)]
	UpDownMixProceesingUnitClusterControlInvalid,
	
	#[allow(missing_docs)]
	UpDownMixProceesingUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	UpDownMixProceesingUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUpDownMixProcessTypeModes(TryReserveError),
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent
	{
		mode: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>,
		
		spatial_location: Version2LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	UpDownMixProcessTypeHasDuplicateMode
	{
		mode: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForDolbyProLogicProcessTypeModes(TryReserveError),
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent
	{
		mode: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>,
		
		spatial_location: Version2LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeHasDuplicateMode
	{
		mode: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogicProceesingUnitModeSelectControlInvalid,
	
	#[allow(missing_docs)]
	DolbyProLogicProceesingUnitClusterControlInvalid,
	
	#[allow(missing_docs)]
	DolbyProLogicProceesingUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	DolbyProLogicProceesingUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	DolbyProLogicProcessTypeCanNotHaveThisMode(DolbyProLogicModeConversionError),
	
	#[allow(missing_docs)]
	StereoExtenderProcessTypeMustNotHaveProcessTypeSpecificBytes,
	
	#[allow(missing_docs)]
	StereoExtenderProcessTypeMustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	StereoExtenderProcessingUnitWidthControlInvalid,
	
	#[allow(missing_docs)]
	StereoExtenderProcessingUnitClusterControlInvalid,
	
	#[allow(missing_docs)]
	StereoExtenderProcessingUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	StereoExtenderProcessingUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForProcessTypeUnrecognizedData(TryReserveError),
}

impl Display for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2ProcessTypeParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForProcessTypeUndefinedData(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUpDownMixProcessTypeModes(cause) => Some(cause),
			
			CouldNotAllocateMemoryForDolbyProLogicProcessTypeModes(cause) => Some(cause),
			
			CouldNotAllocateMemoryForProcessTypeUnrecognizedData(cause) => Some(cause),
			
			DolbyProLogicProcessTypeCanNotHaveThisMode(cause) => Some(cause),
			
			_ => None,
		}
	}
}
