// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version1FeatureUnitEntity
{
	input_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
	
	controls_by_channel_number: Vec<BitFlags<AudioChannelFeatureControl>>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version1FeatureUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version1EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version1EntityDescriptorParseError::*;
		
		let control_size = parse_control_size(entity_body, 5)?;
		
		const ControlSizeSize: usize = 1;
		const StringDescriptorSize: usize = 1;
		let controls_bytes_length = entity_body.len() - ControlSizeSize - StringDescriptorSize;
		if unlikely!(controls_bytes_length % control_size.get() != 0)
		{
			return Err(FeatureUnitControlsHaveRemainder)
		}
		if unlikely!(((Version1EntityDescriptors::FeatureUnitMinimumBLength as usize) + controls_bytes_length) != (DescriptorEntityMinimumLength + entity_body.len()))
		{
			return Err(FeatureUnitLengthWrong)
		}
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_cluster: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<4>()).map(UnitOrTerminalEntityIdentifier::new),
					
					controls_by_channel_number: Self::parse_controls_by_channel_number(controls_bytes_length, control_size, entity_body)?,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8_unadjusted(entity_body.len() - 1)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version1FeatureUnitEntity
{
}

impl Version1FeatureUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn number_of_logical_channels(&self) -> usize
	{
		let length = self.controls_by_channel_number.len();
		if unlikely!(length == 0)
		{
			0
		}
		else
		{
			length - 1
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn master_channel_controls(&self) -> Option<BitFlags<AudioChannelFeatureControl>>
	{
		if unlikely!(self.controls_by_channel_number.is_empty())
		{
			None
		}
		else
		{
			Some(self.controls_by_channel_number.get_unchecked_value_safe(0))
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn logical_channel_controls(&self, logical_audio_channel_number: LogicalAudioChannelNumber) -> Option<BitFlags<AudioChannelFeatureControl>>
	{
		self.controls_by_channel_number.get(logical_audio_channel_number.get()).map(|control| *control)
	}
	
	#[inline(always)]
	fn parse_controls_by_channel_number(controls_bytes_length: usize, control_size: NonZeroUsize, entity_body: &[u8]) -> Result<Vec<BitFlags<AudioChannelFeatureControl>>, Version1EntityDescriptorParseError>
	{
		let number_of_channels_including_master = controls_bytes_length / control_size.get();
		
		let mut controls_by_channel_number = Vec::new_with_capacity(number_of_channels_including_master).map_err(Version1EntityDescriptorParseError::CouldNotAllocateMemoryForFeatureControls)?;
		for index in 0 .. number_of_controls
		{
			let control_bit_map = entity_body.bytes_unadjusted(6 + (index * control_size.get()), control_size.get());
			let controls = if control_size == new_non_zero_usize(1)
			{
				let lower_byte = control_bit_map.get_unchecked_value_safe(0);
				let value = lower_byte as u16;
				unsafe { BitFlags::from_bits_unchecked(value) }
			}
			else
			{
				let lower_byte = control_bit_map.get_unchecked_value_safe(0);
				let upper_byte = control_bit_map.get_unchecked_value_safe(1);
				let value = ((upper_byte as u16) << 8) | (lower_byte as u16);
				BitFlags::from_bits_truncate(value)
			};
			controls_by_channel_number.push(controls);
		}
		
		Ok(controls_by_channel_number)
	}
}
