// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A feature unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1FeatureUnitEntity
{
	input_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
	
	controls_by_channel_number: ChannelControlsByChannelNumber<WrappedBitFlags<Version1AudioChannelFeatureControl>>,
	
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
		
		let control_size = parse_control_size(entity_body, 5, FeatureUnitControlSizeIsZero)?;
		
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
	pub fn input_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.input_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn controls_by_channel_number(&self) -> &ChannelControlsByChannelNumber<WrappedBitFlags<Version1AudioChannelFeatureControl>>
	{
		&self.controls_by_channel_number
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse_controls_by_channel_number(controls_bytes_length: usize, control_size: NonZeroUsize, entity_body: &[u8]) -> Result<ChannelControlsByChannelNumber<WrappedBitFlags<Version1AudioChannelFeatureControl>>, Version1EntityDescriptorParseError>
	{
		let number_of_channels_including_master = controls_bytes_length / control_size.get();
		
		let mut controls_by_channel_number = Vec::new_with_capacity(number_of_channels_including_master).map_err(Version1EntityDescriptorParseError::CouldNotAllocateMemoryForFeatureControls)?;
		for index in 0 .. number_of_channels_including_master
		{
			let control_bit_map = entity_body.bytes_unadjusted(6 + (index * control_size.get()), control_size.get());
			let controls = if control_size == new_non_zero_usize(1)
			{
				let lower_byte = control_bit_map.get_unchecked_value_safe(0);
				let value = lower_byte as u16;
				WrappedBitFlags::from_bits_unchecked(value)
			}
			else
			{
				let lower_byte = control_bit_map.get_unchecked_value_safe(0);
				let upper_byte = control_bit_map.get_unchecked_value_safe(1);
				let value = ((upper_byte as u16) << 8) | (lower_byte as u16);
				WrappedBitFlags::from_bits_truncate(value)
			};
			controls_by_channel_number.push(controls);
		}
		
		Ok(ChannelControlsByChannelNumber(controls_by_channel_number))
	}
}
