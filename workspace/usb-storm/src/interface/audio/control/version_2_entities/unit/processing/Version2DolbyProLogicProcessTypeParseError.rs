// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2DolbyProLogicProcessTypeParseError
{
	#[allow(missing_docs)]
	MustHaveOnlyOneInputPin,
	
	#[allow(missing_docs)]
	MustHaveAtLeastOneByteOfProcessSpecificData,
	
	#[allow(missing_docs)]
	ModeSelectControlInvalid,
	
	#[allow(missing_docs)]
	ClusterControlInvalid,
	
	#[allow(missing_docs)]
	UnderflowControlInvalid,
	
	#[allow(missing_docs)]
	OverflowControlInvalid,
	
	#[allow(missing_docs)]
	CanNotHaveThisMode(DolbyProLogicModeConversionError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForModes(TryReserveError),
	
	#[allow(missing_docs)]
	CanNotHaveThisModeAsASpatialChannelOutputIsAbsent
	{
		mode: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>,
		
		spatial_location: Version2LogicalAudioChannelSpatialLocation,
	},
	
	#[allow(missing_docs)]
	HasDuplicateMode
	{
		mode: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>,
	},
}

impl Display for Version2DolbyProLogicProcessTypeParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2DolbyProLogicProcessTypeParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2DolbyProLogicProcessTypeParseError::*;
		
		match self
		{
			CanNotHaveThisMode(cause) => Some(cause),
			
			CouldNotAllocateMemoryForModes(cause) => Some(cause),
			
			_ => None,
		}
	}
}
