// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	GeneralBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	GeneralBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatTypeBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatTypeIBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeIBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatTypeIIBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeIIBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatTypeIIIBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeIIIBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	DescriptorTypeIsNotInterface
	{
		bDescriptorType: DescriptorType,
	},
	
	#[allow(missing_docs)]
	DescriptorSubTypeIsNotFormatType
	{
		bDescriptorSubType: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	DescriptorSubTypeIsNotFormatSpecific
	{
		bDescriptorSubType: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	UndefinedFormatType
	{
		audio_format: Version1AudioFormat,
	},
	
	#[allow(missing_docs)]
	UnrecognizedFormatType
	{
		audio_format: Version1AudioFormat,
		
		bFormatType: u8,
	},
	
	#[allow(missing_docs)]
	InvalidTypeISubframeSize
	{
		bSubframeSize: u8,
	},
	
	#[allow(missing_docs)]
	ContinuousSamplingFrequencyBLengthWrong
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	ContinuousSamplingFrequencyLengthWrong
	{
		length: usize,
	},
	
	#[allow(missing_docs)]
	ContinuousSamplingFrequencyBoundsNegative
	{
		lower_bound: Hertz,
		
		upper_bound: Hertz,
	},
	
	#[allow(missing_docs)]
	DiscreteSamplingFrequencyBLengthWrong
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	DiscreteSamplingFrequencyLengthWrong
	{
		length: usize,
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForTypeIDiscreteSamplingFrequencies(TryReserveError),
	
	#[allow(missing_docs)]
	InvalidTypeIIISubframeSize
	{
		bSubframeSize: u8,
	},
	
	#[allow(missing_docs)]
	InvalidTypeIIIBitResolution
	{
		bBitResolution: u8,
	},
	
	#[allow(missing_docs)]
	NoRemainingBytesForTypeIIFormatSpecificDescriptor,
	
	#[allow(missing_docs)]
	FormatSpecificBLengthIsLessThanFive,
	
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
	CouldNotAllocateMemoryForUndefinedTypeIIFormatSpecificData(TryReserveError),
}

impl Display for Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForTypeIDiscreteSamplingFrequencies(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUndefinedTypeIIFormatSpecificData(cause) => Some(cause),
			
			_ => None,
		}
	}
}
