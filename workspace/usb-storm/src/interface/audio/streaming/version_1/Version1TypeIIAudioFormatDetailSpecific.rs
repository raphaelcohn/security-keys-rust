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
	MPEG
	{
		internal_dynamic_range_control: InternalDynamicRangeControl,
		
		layer_support: WrappedBitFlags<MpegLayer>,
		
		mpeg_1_only: bool,
		
		mpeg_1_dual_channel: bool,
		
		mpeg_2_second_stereo: bool,
		
		mpeg_2_seven_dot_one_channel_augmentation: bool,
		
		adaptive_multi_channel_prediction: bool,
		
		mpeg_2_multilingual_support: Mpeg2MultilingualSupport,
	},
	
	/// AC-3.
	AC_3
	{
		internal_dynamic_range_control: InternalDynamicRangeControl,
		
		bit_stream_id_modes: WrappedBitFlags<BitStreamIdMode>,
	
		rf_mode: bool,
	
		line_mode: bool,
	
		custom0_mode: bool,
	
		custom1_mode: bool,
	},
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
		
		Ok
		(
			Version1TypeIIAudioFormatDetailSpecific::MPEG
			{
				internal_dynamic_range_control:
				{
					let bmMPEGFeature = remaining_bytes.u16(7);
					InternalDynamicRangeControl::from_2_bits((bmMPEGFeature >> 4) as u8)
				},
				
				layer_support: WrappedBitFlags::from_bits_truncate(bmMPEGCapabilities as u8),
				
				mpeg_1_only: (bmMPEGCapabilities & 0b1000) != 0,
				
				mpeg_1_dual_channel: (bmMPEGCapabilities & 0b0001_0000) != 0,
				
				mpeg_2_second_stereo: (bmMPEGCapabilities & 0b0010_0000) != 0,
				
				mpeg_2_seven_dot_one_channel_augmentation: (bmMPEGCapabilities & 0b0100_0000) != 0,
				
				adaptive_multi_channel_prediction: (bmMPEGCapabilities & 0b1000_0000) != 0,
				
				mpeg_2_multilingual_support:
				{
					use Mpeg2MultilingualSupport::*;
					match (bmMPEGCapabilities >> 8) & 0b11
					{
						0b00 => NotSupported,
						
						0b01 => SupportedAtFs,
						
						0b10 => return Err(ReservedMpeg2MultilingualSupport),
						
						0b11 => SupportedAtFsAndHalfFs,
					}
				},
			}
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
		
		let bmAC3Features = remaining_bytes.u9(9);
		
		Ok
		(
			Version1TypeIIAudioFormatDetailSpecific::AC_3
			{
				internal_dynamic_range_control: InternalDynamicRangeControl::from_2_bits(bmAC3Features >> 4),
				
				bit_stream_id_modes:
				{
					let bmBSID = remaining_bytes.u32(5);
					const Lower9Modes: u32 = 0b1_1111_1111;
					if (bmBSID & Lower9Modes) != Lower9Modes
					{
						return Err(Ac3MustSupportBitStreamIdModes0To9Inclusive)
					}
					WrappedBitFlags::from_bits_unchecked(bmBSID)
				},
				
				rf_mode: (bmAC3Features & 0b0001) != 0,
				
				line_mode: (bmAC3Features & 0b0010) != 0,
				
				custom0_mode: (bmAC3Features & 0b0100) != 0,
				
				custom1_mode: (bmAC3Features & 0b1000) != 0
			}
		)
	}
}
