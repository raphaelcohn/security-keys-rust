// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific AS interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1AudioStreamingInterfaceExtraDescriptor
{
	terminal_link: Option<TerminalEntityIdentifier>,

	delay_in_number_of_frames: u8,

	audio_format_detail: Version1AudioFormatDetail,
}

impl Version1AudioStreamingInterfaceExtraDescriptor
{
	pub(super) const AS_DESCRIPTOR_UNDEFINED: u8 = 0x00;
	
	pub(super) const AS_GENERAL: u8 = 0x01;
	
	pub(super) const FORMAT_TYPE: u8 = 0x02;
	
	pub(super) const FORMAT_SPECIFIC: u8 = 0x03;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn terminal_link(&self) -> Option<TerminalEntityIdentifier>
	{
		self.terminal_link
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn delay_in_number_of_frames(&self) -> u8
	{
		self.delay_in_number_of_frames
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn audio_format_detail(&self) -> &Version1AudioFormatDetail
	{
		&self.audio_format_detail
	}
	
	#[inline(always)]
	pub(super) fn parse(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8]) -> Result<(Self, usize), Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		const BLength: u8 = 7;
		
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, BLength>(descriptor_body_followed_by_remaining_bytes, bLength, GeneralBLengthIsLessThanMinimum, GeneralBLengthExceedsRemainingBytes)?;
		
		let audio_format = Version1AudioFormat::parse(descriptor_body.u16(descriptor_index::<5>()));
		
		let audio_format_descriptor_followed_by_remaining_bytes = descriptor_body_followed_by_remaining_bytes.get_unchecked_range_safe(descriptor_body_length .. );
		
		let (audio_format_detail, audio_format_detail_consumed_length) = Self::parse_format_type_descriptor(audio_format, audio_format_descriptor_followed_by_remaining_bytes)?;
		
		Ok
		(
			(
				Version1AudioStreamingInterfaceExtraDescriptor
				{
					terminal_link: descriptor_body.optional_non_zero_u8(descriptor_index::<3>()),
					
					delay_in_number_of_frames: descriptor_body.u8(descriptor_index::<4>()),
				
					audio_format_detail,
				},
				
				descriptor_body_length + audio_format_detail_consumed_length,
			)
		)
	}
	
	#[inline(always)]
	fn parse_format_type_descriptor(audio_format: Version1AudioFormat, audio_format_descriptor_followed_by_remaining_bytes: &[u8]) -> Result<(Version1AudioFormatDetail, usize), FormatTypeParseError>
	{
		use FormatTypeParseError::*;
		
		let bLength =
		{
			if unlikely!(audio_format_descriptor_followed_by_remaining_bytes.is_empty())
			{
				return Err(NoFormatTypeDescriptorBytes)
			}
			audio_format_descriptor_followed_by_remaining_bytes.u8(0)
		};
		if unlikely!((bLength as usize) < DescriptorHeaderLength)
		{
			return Err(BLengthIsLessThanDescriptorHeaderLength)
		}
		
		{
			let bDescriptorType = audio_format_descriptor_followed_by_remaining_bytes.u8(1);
			if unlikely!(bDescriptorType != CS_INTERFACE)
			{
				return Err(DescriptorTypeIsNotInterface { bDescriptorType })
			}
		}
		
		const MinimumBLength: u8 = 4;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(audio_format_descriptor_followed_by_remaining_bytes.get_unchecked_range_safe(DescriptorHeaderLength .. ), bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		{
			let bDescriptorSubType = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(bDescriptorSubType != Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_TYPE)
			{
				return Err(DescriptorSubTypeIsNotFormatType { bDescriptorSubType })
			}
		}
		
		use Version1AudioFormat::*;
		let bFormatType = descriptor_body.u8(descriptor_index::<3>());
		let (outcome, consumed_length) = match (bFormatType, audio_format)
		{
			(0x00, _) => return Err(UndefinedFormatTypeCode { audio_format }),
			
			(0x01, TypeI(format)) => (Version1TypeIAudioFormatDetail::parse(format, bLength, descriptor_body)?, 0),
			
			(0x02, TypeII(format)) => Version1TypeIIAudioFormatDetail::parse(format, bLength, descriptor_body, descriptor_body_length, audio_format_descriptor_followed_by_remaining_bytes)?,
			
			(0x03, TypeIII(format)) => (Version1TypeIIIAudioFormatDetail::parse(format, bLength, descriptor_body)?, 0),
			
			(_, _) => return Err(UnrecognizedFormatTypeCode { audio_format, bFormatType })
		};
		Ok((outcome, (bLength as usize) + consumed_length))
	}
}
