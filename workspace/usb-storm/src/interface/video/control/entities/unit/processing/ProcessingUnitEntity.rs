// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Processing unit entity descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingUnitEntity
{
	source: Option<EntityIdentifier>,
	
	digital_multiplier: Option<DigitalMultiplier>,
	
	controls: WrappedBitFlags<ProcessingControl>,
	
	analog_video: Option<AnalogVideo>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for ProcessingUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = ProcessingUnitEntityParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], device_connection: &DeviceConnection, specification_version: Version) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use ProcessingUnitEntityParseError::*;
		
		let minimum_b_length = Self::choose_minimum_b_length(specification_version);
		
		if unlikely!(bLengthUsize < minimum_b_length)
		{
			return Err(BLengthTooShort { bLength: bLengthUsize as u8 })
		}
		
		let (controls_bit_map, controls, index_after_controls) = Self::parse_controls(bLengthUsize, entity_body, specification_version, minimum_b_length)?;
		
		Ok
		(
			Alive
			(
				Self
				{
					source: entity_body.optional_non_zero_u8(entity_index::<4>()),
					
					digital_multiplier: DigitalMultiplier::parse(entity_body, controls_bit_map, specification_version)?,
					
					controls,
					
					analog_video: AnalogVideo::parse(entity_body, controls_bit_map, index_after_controls, specification_version)?,
					
					description:
					{
						let dead_or_alive = device_connection.find_string(entity_body.u8(entity_index_non_constant(index_after_controls))).map_err(InvalidDescriptionString)?;
						return_ok_if_dead!(dead_or_alive)
					},
				}
			)
		)
	}
	
	#[inline(always)]
	fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}

impl WithSourceEntity for ProcessingUnitEntity
{
	#[inline(always)]
	fn source(&self) -> Option<EntityIdentifier>
	{
		self.source
	}
}

impl UnitEntity for ProcessingUnitEntity
{
}

impl ProcessingUnitEntity
{
	
	#[inline(always)]
	fn choose_minimum_b_length(specification_version: Version) -> usize
	{
		if likely!(specification_version.is_1_1_or_greater())
		{
			10
		}
		else
		{
			9
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn digital_multiplier(&self) -> Option<DigitalMultiplier>
	{
		self.digital_multiplier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn controls(&self) -> WrappedBitFlags<ProcessingControl>
	{
		self.controls
	}
	
	/// This is always `None` for if the specification version is 1.0.
	#[inline(always)]
	pub const fn analog_video(&self) -> Option<AnalogVideo>
	{
		self.analog_video
	}
	
	#[inline(always)]
	fn parse_controls(bLengthUsize: usize, entity_body: &[u8], specification_version: Version, minimum_b_length: usize) -> Result<(u32, WrappedBitFlags<ProcessingControl>, usize), ProcessingUnitEntityParseError>
	{
		use ProcessingUnitEntityParseError::*;
		
		let bControlSize = entity_body.u8(entity_index::<7>());
		const AllSpecificationVersionsBitMaskWithoutDigitalMultiplierOrAnalogVideo: u32 = 0b0000_0011_1111_1111_1111;
		let bit_mask = if specification_version.is_1_5_or_greater()
		{
			if unlikely!(bControlSize != 3)
			{
				return Err(Version_1_5_HasInvalidControlSize { bControlSize })
			}
			const Bit18: u32 = 1 << 18;
			const BitMask: u32 = AllSpecificationVersionsBitMaskWithoutDigitalMultiplierOrAnalogVideo | Bit18;
			BitMask
		}
		else
		{
			AllSpecificationVersionsBitMaskWithoutDigitalMultiplierOrAnalogVideo
		};
		
		let controls_size = bControlSize as usize;
		if unlikely!(bLengthUsize < (minimum_b_length + controls_size))
		{
			return Err(BLengthTooShortForControlSize { bLength: bLengthUsize as u8, bControlSize, specification_version })
		}
		
		const ControlsIndex: usize = 8;
		let bmControls = entity_body.bytes(entity_index::<ControlsIndex>(), controls_size);
		let controls_bit_map = match controls_size
		{
			0 => 0,
			
			1 => bmControls.u8_as_u32(0),
			
			2 => bmControls.u16_as_u32(0),
			
			3 => bmControls.u24_as_u32(0),
			
			_ => bmControls.u32(0),
		};
		
		let controls = WrappedBitFlags::from_bits_unchecked(controls_bit_map & bit_mask);
		let index_after_controls = ControlsIndex + controls_size;
		Ok((controls_bit_map, controls, index_after_controls))
	}
}
