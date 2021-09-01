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
	pub(super) fn parse(bLength: u8, remaining_bytes: &[u8]) -> Result<(Self, usize), Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		const BLength: u8 = 7;
		
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<Version1AudioStreamingInterfaceExtraDescriptorParseError, BLength>(remaining_bytes, bLength, GeneralBLengthIsLessThanMinimum, GeneralBLengthExceedsRemainingBytes)?;
		
		let audio_format = Version1AudioFormat::parse(descriptor_body.u16(descriptor_index::<5>()));
		
		let (audio_format_detail, audio_format_detail_consumed_length) = Self::parse_audio_format(audio_format, remaining_bytes.get_unchecked_range_safe(((BLength as usize) - DescriptorHeaderLength) .. ))?;
		
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
	fn parse_audio_format(audio_format: Version1AudioFormat, remaining_bytes: &[u8]) -> Result<(Version1AudioFormatDetail, usize), Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		let bLength = remaining_bytes.u8(0);
		let _ = verify_remaining_bytes::<Version1AudioStreamingInterfaceExtraDescriptorParseError, 4>(remaining_bytes, bLength, FormatTypeBLengthIsLessThanMinimum, FormatTypeBLengthExceedsRemainingBytes)?;
		
		let bDescriptorType = remaining_bytes.u8(1);
		if unlikely!(bDescriptorType != AudioControlInterfaceExtraDescriptorParser::CS_INTERFACE)
		{
			return Err(DescriptorTypeIsNotInterface { bDescriptorType })
		}
		
		let bDescriptorSubType = remaining_bytes.u8(2);
		if unlikely!(bDescriptorSubType != Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_TYPE)
		{
			return Err(DescriptorSubTypeIsNotFormatType { bDescriptorSubType })
		}
		
		use Version1AudioFormat::*;
		let bFormatType = remaining_bytes.u8(3);
		match (bFormatType, audio_format)
		{
			(0x00, _) => Err(UndefinedFormatType { audio_format }),
			
			(0x01, TypeI(format)) => Version1TypeIAudioFormatDetail::parse(format, bLength, remaining_bytes),
			
			(0x02, TypeII(format)) => Version1TypeIIAudioFormatDetail::parse(format, bLength, remaining_bytes),
			
			(0x03, TypeIII(format)) => Version1TypeIIIAudioFormatDetail::parse(format, bLength, remaining_bytes),
			
			(_, _) => Err(UnrecognizedFormatType { audio_format, bFormatType })
		}
	}
}
