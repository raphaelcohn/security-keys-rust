// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version1ProcessTypeParseError
{
	#[allow(missing_docs)]
	Undefined(Version1UndefinedProcessTypeParseError),
	
	#[allow(missing_docs)]
	UpDownMix(Version1UpDownMixProcessTypeParseError),
	
	#[allow(missing_docs)]
	DolbyProLogic(Version1DolbyProLogicProcessTypeParseError),
	
	#[allow(missing_docs)]
	ThreeDimensionalStereoExtended(Version1ThreeDimensionalStereoExtendedProcessTypeParseError),
	
	#[allow(missing_docs)]
	Reverberation(Version1ReverberationProcessTypeParseError),
	
	#[allow(missing_docs)]
	Chorus(Version1ChorusProcessTypeParseError),
	
	#[allow(missing_docs)]
	DynamicRangeCompressor(Version1DynamicRangeCompressorProcessTypeParseError),
	
	#[allow(missing_docs)]
	Unrecognized(Version1UnrecognizedProcessTypeParseError),
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
			Undefined(cause) => Some(cause),
			
			UpDownMix(cause) => Some(cause),
			
			DolbyProLogic(cause) => Some(cause),
			
			ThreeDimensionalStereoExtended(cause) => Some(cause),
			
			Reverberation(cause) => Some(cause),
			
			Chorus(cause) => Some(cause),
			
			DynamicRangeCompressor(cause) => Some(cause),
			
			Unrecognized(cause) => Some(cause),
		}
	}
}

impl From<Version1UndefinedProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1UndefinedProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::Undefined(cause)
	}
}

impl From<Version1UpDownMixProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1UpDownMixProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::UpDownMix(cause)
	}
}

impl From<Version1DolbyProLogicProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1DolbyProLogicProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::DolbyProLogic(cause)
	}
}

impl From<Version1ThreeDimensionalStereoExtendedProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1ThreeDimensionalStereoExtendedProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::ThreeDimensionalStereoExtended(cause)
	}
}

impl From<Version1ReverberationProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1ReverberationProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::Reverberation(cause)
	}
}

impl From<Version1ChorusProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1ChorusProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::Chorus(cause)
	}
}

impl From<Version1DynamicRangeCompressorProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1DynamicRangeCompressorProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::DynamicRangeCompressor(cause)
	}
}

impl From<Version1UnrecognizedProcessTypeParseError> for Version1ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version1UnrecognizedProcessTypeParseError) -> Self
	{
		Version1ProcessTypeParseError::Unrecognized(cause)
	}
}
