// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatTypeIIParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanDescriptorHeaderLength,
	
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	SamplingFrequencyParse(SamplingFrequencyParseError),
	
	#[allow(missing_docs)]
	NoRemainingBytesForFormatSpecificDescriptor,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthIsLessThanFive,
	
	#[allow(missing_docs)]
	DescriptorTypeIsNotInterface
	{
		bDescriptorType: DescriptorType,
	},
	
	#[allow(missing_docs)]
	DescriptorSubTypeIsNotFormatSpecific
	{
		bDescriptorSubType: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	MismatchedFormatTagsInFormatSpecifcDescriptor
	{
		format: Version1TypeIIAudioFormat,
		
		wFormatTag: u16,
	},
	
	#[allow(missing_docs)]
	FormatSpecificBLengthIsLessThanNineForMpeg,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthIsLessThanTenForAc3,
	
	#[allow(missing_docs)]
	ReservedMpeg2MultilingualSupport,
	
	#[allow(missing_docs)]
	Ac3MustSupportBitStreamIdModes0To9Inclusive,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUndefinedFormatSpecificData(TryReserveError),
}

impl Display for FormatTypeIIParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for FormatTypeIIParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use FormatTypeIIParseError::*;
		
		match self
		{
			SamplingFrequencyParse(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUndefinedFormatSpecificData(cause) => Some(cause),
			
			_ => None,
		}
	}
}
