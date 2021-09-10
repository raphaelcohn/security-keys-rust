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
		value
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version1FeatureUnitEntityParseError::*;
		
		let input_logical_audio_channel_cluster = entity_body.optional_non_zero_u8(entity_index::<4>()).map(UnitOrTerminalEntityIdentifier::new);
		let control_size = parse_control_size(entity_body, 5, UnitControlSizeIsZero)?;
		let description = return_ok_if_dead!(device_connection.find_string(entity_body.u8(entity_body.len() - 1)).map_err(InvalidDescriptionString)?);
		
		const SourceIdSize: usize = 1;
		const ControlSizeSize: usize = 1;
		const StringDescriptorSize: usize = 1;
		let controls_bytes_length = entity_body.len() - SourceIdSize - ControlSizeSize - StringDescriptorSize;
		if unlikely!(((Version1EntityDescriptors::FeatureUnitMinimumBLength as usize) + controls_bytes_length) != (DescriptorEntityMinimumLength + entity_body.len()))
		{
			Err(BLengthWrong)?
		}
		if unlikely!(controls_bytes_length % control_size.get() != 0)
		{
			Err(UnitControlsHaveRemainder { controls_bytes_length, control_size } )?
		}
		
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_cluster,
					
					controls_by_channel_number: Self::parse_controls_by_channel_number(controls_bytes_length, control_size, entity_body)?,
					
					description,
				}
			)
		)
	}
}

impl DescribedEntity for Version1FeatureUnitEntity
{
	#[inline(always)]
	fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}

impl Version1Entity for Version1FeatureUnitEntity
{
}

impl UnitEntity for Version1FeatureUnitEntity
{
}

impl FeatureUnitEntity for Version1FeatureUnitEntity
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
	
	#[inline(always)]
	fn parse_controls_by_channel_number(controls_bytes_length: usize, control_size: NonZeroUsize, entity_body: &[u8]) -> Result<ChannelControlsByChannelNumber<WrappedBitFlags<Version1AudioChannelFeatureControl>>, Version1FeatureUnitEntityParseError>
	{
		let control_size = control_size.get();
		let number_of_channels_including_master = controls_bytes_length / control_size;
		
		if control_size == 1
		{
			Self::channel_controls_by_channel_number(control_size, number_of_channels_including_master, entity_body, |lower_byte, _remaining_control_bit_map|
			{
				let value = lower_byte as u16;
				WrappedBitFlags::from_bits_unchecked(value)
			})
		}
		else
		{
			Self::channel_controls_by_channel_number(control_size, number_of_channels_including_master, entity_body, |lower_byte, remaining_control_bit_map|
			{
				let upper_byte = remaining_control_bit_map.get_unchecked_value_safe(1);
				let value = ((upper_byte as u16) << 8) | (lower_byte as u16);
				WrappedBitFlags::from_bits_truncate(value)
			})
		}
	}
	
	#[inline(always)]
	fn channel_controls_by_channel_number(control_size: usize, number_of_channels_including_master: usize, entity_body: &[u8], controls_parse: impl Fn(u8, &[u8]) -> WrappedBitFlags<Version1AudioChannelFeatureControl>) -> Result<ChannelControlsByChannelNumber<WrappedBitFlags<Version1AudioChannelFeatureControl>>, Version1FeatureUnitEntityParseError>
	{
		Vec::new_populated(number_of_channels_including_master, Version1FeatureUnitEntityParseError::CouldNotAllocateMemoryForControls, |index|
		{
			let control_bit_map = entity_body.bytes(entity_index_non_constant(6 + (index * control_size)), control_size);
			let lower_byte = control_bit_map.get_unchecked_value_safe(0);
			Ok(controls_parse(lower_byte, control_bit_map.get_unchecked_range_safe(1 .. )))
		}).map(ChannelControlsByChannelNumber)
	}
}
