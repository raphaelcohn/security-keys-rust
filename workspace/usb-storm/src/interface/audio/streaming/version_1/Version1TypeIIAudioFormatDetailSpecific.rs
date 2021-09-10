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
	fn parse(format: Version1TypeIIAudioFormat, audio_format_specific_descriptor_bytes: &[u8]) -> Result<(Self, usize), FormatTypeIIParseError>
	{
		use Version1TypeIIAudioFormat::*;
		use FormatTypeIIParseError::*;
		
		if unlikely!(audio_format_specific_descriptor_bytes.is_empty())
		{
			return if unlikely!(format == Undefined)
			{
				Ok((Version1TypeIIAudioFormatDetailSpecific::Undefined(Vec::new()), 0))
			}
			else
			{
				Err(NoRemainingBytesForFormatSpecificDescriptor)
			}
		}
		
		let bLength = audio_format_specific_descriptor_bytes.u8(0);
		if unlikely!((bLength as usize) < DescriptorHeaderLength)
		{
			return Err(BLengthIsLessThanDescriptorHeaderLength)
		}
		
		{
			let bDescriptorType = audio_format_specific_descriptor_bytes.u8(1);
			if unlikely!(bDescriptorType != CS_INTERFACE)
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
		}
		
		let (descriptor_body, descriptor_body_length) =
		{
			const MinimumBLength: u8 = 3;
			verify_remaining_bytes::<_, MinimumBLength>(audio_format_specific_descriptor_bytes.get_unchecked_range_safe(DescriptorHeaderLength .. ), bLength, FormatSpecificBLengthIsLessThanMinimum, FormatSpecificBLengthExceedsRemainingBytes)?
		};
		
		{
			let bDescriptorSubType = descriptor_body.u8(descriptor_index::<2>());
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
		}
		
		if unlikely!(bLength < Self::BLengthFive)
		{
			return Err(FormatSpecificBLengthIsLessThanFive)
		}
		let wFormatTag = descriptor_body.u16(descriptor_index::<3>());
		
		Ok
		(
			(
				match (format, wFormatTag)
				{
					(Undefined, Version1AudioFormat::TypeIIUndefined) => Self::parse_undefined(descriptor_body, descriptor_body_length),
					
					(MPEG, Version1AudioFormat::TypeIIMPEG) => Self::parse_mpeg(descriptor_body, bLength),
					
					(AC_3, Version1AudioFormat::TypeIIAC_3) => Self::parse_ac_3(descriptor_body, bLength),
					
					_ => return Err(MismatchedFormatTagsInFormatSpecifcDescriptor { format, wFormatTag })
				}?,
				
				bLength as usize,
			)
		)
	}
	
	#[inline(always)]
	fn parse_undefined(descriptor_body: &[u8], descriptor_body_length: usize) -> Result<Self, FormatTypeIIParseError>
	{
		const Start: usize = (Version1TypeIIAudioFormatDetailSpecific::BLengthFive as usize) - DescriptorHeaderLength;
		let data = Vec::new_from(descriptor_body.get_unchecked_range_safe(Start .. descriptor_body_length)).map_err(FormatTypeIIParseError::CouldNotAllocateMemoryForUndefinedFormatSpecificData)?;
		Ok(Version1TypeIIAudioFormatDetailSpecific::Undefined(data))
	}
	
	#[inline(always)]
	fn parse_mpeg(descriptor_body: &[u8], bLength: u8) -> Result<Self, FormatTypeIIParseError>
	{
		use FormatTypeIIParseError::*;
		
		if unlikely!(bLength < 9)
		{
			return Err(FormatSpecificBLengthIsLessThanNineForMpeg)
		}
		
		let bmMPEGCapabilities = descriptor_body.u16(descriptor_index::<5>());
		let bmMPEGFeatures = descriptor_body.u8(descriptor_index::<7>());
		
		Ok
		(
			Version1TypeIIAudioFormatDetailSpecific::MPEG(MpegCommon::parse(bmMPEGCapabilities, bmMPEGFeatures, ReservedMpeg2MultilingualSupport)?)
		)
	}
	
	#[inline(always)]
	fn parse_ac_3(descriptor_body: &[u8], bLength: u8) -> Result<Self, FormatTypeIIParseError>
	{
		use FormatTypeIIParseError::*;
		
		if unlikely!(bLength < 10)
		{
			return Err(FormatSpecificBLengthIsLessThanTenForAc3)
		}
		
		Ok
		(
			Version1TypeIIAudioFormatDetailSpecific::AC_3(Ac3Common::parse(descriptor_body, Ac3MustSupportBitStreamIdModes0To9Inclusive)?),
		)
	}
}
