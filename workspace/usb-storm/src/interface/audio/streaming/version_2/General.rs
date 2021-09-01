// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// General
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct General
{
	terminal_link: Option<TerminalEntityIdentifier>,
	
	active_alternate_setting_control: Control,
	
	valid_alternate_setting_control: Control,

	logical_audio_channel_cluster: Version2LogicalAudioChannelCluster,

	audio_format: Version2AudioFormatDetails,
}

impl General
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn terminal_link(&self) -> Option<TerminalEntityIdentifier>
	{
		self.terminal_link
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn active_alternate_setting_control(&self) -> Control
	{
		self.active_alternate_setting_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn valid_alternate_setting_control(&self) -> Control
	{
		self.valid_alternate_setting_control
	}
	
	#[inline(always)]
	fn parse(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, GeneralParseError>
	{
		use GeneralParseError::*;
		use GeneralControlsParseError::*;
		
		const BLength: u8 = 16;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<GeneralParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bmControls = descriptor_body.u8(descriptor_index::<4>());
		
		let general_format_type = descriptor_body.u8(descriptor_index::<5>());
		let formats_bit_map = descriptor_body.u32(descriptor_index::<6>());
		let subsequent_format_type_descriptor_bytes = remaining_bytes.get_unchecked_range_safe(.. (bLength as usize));
		let (subsequent_format_type_descriptor_body, subsequent_format_type_descriptor_body_bLength) = Self::parse_subsequent_format_type_descriptor_header(general_format_type, subsequent_format_type_descriptor_bytes)?;
		
		let consumed_length = subsequent_format_type_descriptor_body_bLength as usize;
		Ok
		(
			Alive
			(
				(
					Self
					{
						terminal_link: descriptor_body.optional_non_zero_u8(descriptor_index::<3>()),
						
						active_alternate_setting_control: Control::parse_u8(bmControls, 0, ActiveAlternateSettingControlInvalid)?,
						
						valid_alternate_setting_control: Control::parse_u8(bmControls, 1, ValidAlternateSettingControlInvalid)?,
						
						logical_audio_channel_cluster:
						{
							let dead_or_alive = Version2LogicalAudioChannelCluster::parse_descriptor(10, string_finder, descriptor_body)?;
							return_ok_if_dead!(dead_or_alive)
						},
					
						audio_format: Version2AudioFormatDetails::parse(general_format_type, formats_bit_map, subsequent_format_type_descriptor_body, subsequent_format_type_descriptor_body_bLength)?,
					},
					
					descriptor_body_length + consumed_length
				)
			)
		)
	}
	
	fn parse_subsequent_format_type_descriptor_header(general_format_type: u8, subsequent_format_type_descriptor_bytes: &[u8]) -> Result<(&[u8], u8), FormatTypeDescriptorParseError>
	{
		use FormatTypeDescriptorParseError::*;
		
		let bLength =
		{
			if unlikely!(subsequent_format_type_descriptor_bytes.is_empty())
			{
				return Err(NoFormatTypeDescriptor)
			}
			subsequent_format_type_descriptor_bytes.u8(0)
		};
		
		const MinimumBLength: u8 = 4;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<FormatTypeDescriptorParseError, MinimumBLength>(subsequent_format_type_descriptor_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		{
			let descriptor_type = descriptor_body.u8(descriptor_index::<1>());
			if unlikely!(descriptor_type != AudioControlInterfaceExtraDescriptorParser::CS_INTERFACE)
			{
				return Err(UnrecognizedInterfaceDescriptorType { descriptor_type })
			}
		}
		
		{
			let descriptor_sub_type = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(descriptor_sub_type != Version2AudioStreamingInterfaceExtraDescriptor::FORMAT_TYPE)
			{
				return Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })
			}
		}
		
		{
			let bFormatType = descriptor_body.u8(descriptor_index::<3>());
			if unlikely!(bFormatType != general_format_type)
			{
				return Err(FormatTypeMismatch { general_format_type, bFormatType })
			}
		}
		
		Ok((descriptor_body, bLength))
	}
}
