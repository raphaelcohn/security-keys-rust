// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Information specific to Type II audio format.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version1TypeIIAudioFormatDetailSpecific
{
	#[allow(missing_docs)]
	Undefined(Vec<u8>),
	
	#[allow(missing_docs)]
	MPEG(MpegCommon),
	
	/// AC-3.
	AC_3(Ac3Common),
}

impl Version1TypeIIAudioFormatDetailSpecific
{
	const BLengthFive: u8 = 5;
	
	#[inline(always)]
	fn parse(format: Version1TypeIIAudioFormat, remaining_bytes: &[u8]) -> Result<(Self, usize), Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version1TypeIIAudioFormat::*;
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		if unlikely!(remaining_bytes.is_empty())
		{
			return if unlikely!(format == Undefined)
			{
				Ok((Version1TypeIIAudioFormatDetailSpecific::Undefined(Vec::new()), 0))
			}
			else
			{
				Err(NoRemainingBytesForTypeIIFormatSpecificDescriptor)
			}
		}
		
		let bLength = remaining_bytes.u8(0);
		const MinimumBLength: u8 = 3;
		let _ = verify_remaining_bytes::<Version1AudioStreamingInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, FormatSpecificBLengthIsLessThanMinimum, FormatSpecificBLengthExceedsRemainingBytes)?;
		
		let bDescriptorType = remaining_bytes.u8(1);
		if unlikely!(bDescriptorType != AudioControlInterfaceExtraDescriptorParser::CS_INTERFACE)
		{
			return if unlikely!(format == Undefined)
			{
				Ok((Version1TypeIIAudioFormatDetailSpecific::Undefined(Vec::new()), 0))
			}
			else
			{
				Err(DescriptorTypeIsNotInterface { bDescriptorType })
			}
		}
		
		let bDescriptorSubType = remaining_bytes.u8(2);
		if unlikely!(bDescriptorSubType != Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_SPECIFIC)
		{
			return if unlikely!(format == Undefined)
			{
				Ok((Version1TypeIIAudioFormatDetailSpecific::Undefined(Vec::new()), 0))
			}
			else
			{
				Err(DescriptorSubTypeIsNotFormatSpecific { bDescriptorSubType })
			}
		}
		
		if unlikely!(bLength < Self::BLengthFive)
		{
			return Err(FormatSpecificBLengthIsLessThanFive)
		}
		let wFormatTag = remaining_bytes.u16(3);
		
		Ok
		(
			(
				match (format, wFormatTag)
				{
					(Undefined, Version1AudioFormat::TypeIIUndefined) => Self::parse_undefined(remaining_bytes, bLength),
					
					(MPEG, Version1AudioFormat::TypeIIMPEG) => Self::parse_mpeg(remaining_bytes, bLength),
					
					(AC_3, Version1AudioFormat::TypeIIAC_3) => Self::parse_ac_3(remaining_bytes, bLength),
					
					_ => return Err(MismatchedFormatTagsInFormatSpecifcDescriptor { format, wFormatTag })
				}?,
				
				bLength as usize,
			)
		)
	}
	
	#[inline(always)]
	fn parse_undefined(remaining_bytes: &[u8], bLength: u8) -> Result<Self, Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		let data = Vec::new_from(remaining_bytes.get_unchecked_range_safe((Self::BLengthFive as usize) ..(bLength as usize))).map_err(Version1AudioStreamingInterfaceExtraDescriptorParseError::CouldNotAllocateMemoryForUndefinedTypeIIFormatSpecificData)?;
		Ok(Version1TypeIIAudioFormatDetailSpecific::Undefined(data))
	}
	
	#[inline(always)]
	fn parse_mpeg(remaining_bytes: &[u8], bLength: u8) -> Result<Self, Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		if unlikely!(bLength < 9)
		{
			return Err(FormatSpecificBLengthIsLessThanNineForMpeg)
		}
		
		let bmMPEGCapabilities = remaining_bytes.u16(5);
		let bmMPEGFeatures = remaining_bytes.u8(7);
		
		Ok
		(
			Version1TypeIIAudioFormatDetailSpecific::MPEG(MpegCommon::parse(bmMPEGCapabilities, bmMPEGFeatures, ReservedMpeg2MultilingualSupport)?)
		)
	}
	
	#[inline(always)]
	fn parse_ac_3(remaining_bytes: &[u8], bLength: u8) -> Result<Self, Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		if unlikely!(bLength < 10)
		{
			return Err(FormatSpecificBLengthIsLessThanTenForAc3)
		}
		
		Ok
		(
			Version1TypeIIAudioFormatDetailSpecific::AC_3(Ac3Common::parse(remaining_bytes, Ac3MustSupportBitStreamIdModes0To9Inclusive)?),
		)
	}
}
