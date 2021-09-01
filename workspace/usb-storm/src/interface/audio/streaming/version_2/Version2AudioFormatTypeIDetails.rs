// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format Type I details.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2AudioFormatTypeIDetails
{
	audio_sub_slot_size_in_bytes: AudioSubSlotSizeInBytes,
	
	bit_resolution: u8,
	
	extended: Option<Version2AudioFormatExtendedTypeIDetails>,
}

impl Version2AudioFormatTypeIDetails
{
	#[inline(always)]
	pub fn extended(&self) -> Option<&Version2AudioFormatExtendedTypeIDetails>
	{
		self.extended.as_ref()
	}
	
	#[inline(always)]
	pub const fn audio_sub_slot_size_in_bytes(&self) -> AudioSubSlotSizeInBytes
	{
		self.audio_sub_slot_size_in_bytes
	}
	
	#[inline(always)]
	pub const fn bit_resolution(&self) -> u8
	{
		self.bit_resolution
	}
	
	#[inline(always)]
	fn parse_unextended(subsequent_format_type_descriptor_body: &[u8]) -> Result<Self, FormatTypeDescriptorParseError>
	{
		Self::parse_common(subsequent_format_type_descriptor_body, None)
	}
	
	#[inline(always)]
	fn parse_extended(subsequent_format_type_descriptor_body: &[u8]) -> Result<Self, FormatTypeDescriptorParseError>
	{
		let extended = Version2AudioFormatExtendedTypeIDetails::parse(subsequent_format_type_descriptor_body);
		Self::parse_common(subsequent_format_type_descriptor_body, Some(extended))
	}
	
	#[inline(always)]
	fn parse_common(subsequent_format_type_descriptor_body: &[u8], extended: Option<Version2AudioFormatExtendedTypeIDetails>) -> Result<Self, FormatTypeDescriptorParseError>
	{
		use AudioSubSlotSizeInBytes::*;
		
		Ok
		(
			Self
			{
				audio_sub_slot_size_in_bytes: match subsequent_format_type_descriptor_body.u8(descriptor_index::<4>())
				{
					1 => One,
					
					2 => Two,
					
					3 => Three,
					
					4 => Four,
					
					bSubslotSize @ _ => return Err(FormatTypeDescriptorParseError::TypeISubslotSizeWrong { bSubslotSize })
				},
			
				bit_resolution: subsequent_format_type_descriptor_body.u8(descriptor_index::<5>()),
			
				extended,
			}
		)
	}
}
