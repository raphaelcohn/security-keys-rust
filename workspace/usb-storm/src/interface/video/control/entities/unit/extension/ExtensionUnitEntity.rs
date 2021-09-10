// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Extension unit entity descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionUnitEntity
{
	extension_code: UniversallyUniqueIdentifier,
	
	sources: Sources,
	
	controls: ExtensionControls,
	
	description: Option<LocalizedStrings>,
}

impl Entity for ExtensionUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = ExtensionUnitEntityParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], device_connection: &DeviceConnection, _specification_version: Version) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use ExtensionUnitEntityParseError::*;
		
		if unlikely!(bLengthUsize < Self::MinimumBLength)
		{
			return Err(BLengthTooShort { bLength: bLengthUsize as u8 })
		}
		
		let (sources, after_sources_index, minimum_b_length) = Self::parse_sources(bLengthUsize, entity_body)?;
		
		let (controls, after_controls_index) = Self::parse_controls(bLengthUsize, entity_body, after_sources_index, minimum_b_length)?;
		
		Ok
		(
			Alive
			(
				Self
				{
					extension_code: entity_body.universally_unique_identifier(entity_index::<4>()),
					
					sources,
					
					controls,
					
					description:
					{
						let dead_or_alive = device_connection.find_string(entity_body.u8(entity_index_non_constant(after_controls_index))).map_err(InvalidDescriptionString)?;
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

impl UnitEntity for ExtensionUnitEntity
{
}

impl WithSourcesUnitEntity for ExtensionUnitEntity
{
	#[inline(always)]
	fn sources(&self) -> &Sources
	{
		&self.sources
	}
}

impl ExtensionUnitEntity
{
	const MinimumBLength: usize = 24;
	
	// /// <https://docs.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5> `{0F3F95DC-2632-4C4E-92C9-A04782F43BC8}`
	// const MS_CAMERA_CONTROL_XU: Uuid = Uuid::from_bytes()
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn extension_code(&self) -> UniversallyUniqueIdentifier
	{
		self.extension_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn controls(&self) -> &ExtensionControls
	{
		&self.controls
	}
	
	#[inline(always)]
	fn parse_sources(bLengthUsize: usize, entity_body: &[u8]) -> Result<(Sources, usize, usize), ExtensionUnitEntityParseError>
	{
		const MinimumBLength: usize = ExtensionUnitEntity::MinimumBLength;
		Ok(Sources::parse::<MinimumBLength, 21>(bLengthUsize, entity_body)?)
	}
	
	#[inline(always)]
	fn parse_controls(bLengthUsize: usize, entity_body: &[u8], after_sources_index: usize, minimum_b_length: usize) -> Result<(ExtensionControls, usize), ExtensionUnitEntityParseError>
	{
		let controls_size = Self::parse_controls_size(bLengthUsize, entity_body, after_sources_index, minimum_b_length)?;
		let after_controls_size_index =
		{
			const ControlsSizeSize: usize = 1;
			after_sources_index + ControlsSizeSize
		};
		let controls = entity_body.bytes(entity_index_non_constant(after_controls_size_index), controls_size);
		
		let raw_controls_u64 = match controls_size
		{
			0 => 0,
			
			1 => controls.u8_as_u64(0),
			
			2 => controls.u16_as_u64(0),
			
			3 => controls.u24_as_u64(0),
			
			4 => controls.u32_as_u64(0),
			
			5 => controls.u40_as_u64(0),
			
			6 => controls.u48_as_u64(0),
			
			7 => controls.u56_as_u64(0),
			
			_ => controls.u64(0),
		};
		
		let (number_of_controls, controls_mask) =
		{
			let bNumControls = entity_body.u8(entity_index::<20>());
			if unlikely!(bNumControls > 64)
			{
				return Err(ExtensionUnitEntityParseError::MoreThan64ExtensionControlsAreNotSupported { bNumControls })
			}
			
			let mask = (1 << (bNumControls as u64)) - 1;
			(bNumControls, mask)
		};
		
		let controls_u64 = raw_controls_u64 & controls_mask;
		
		Ok((ExtensionControls(controls_u64, number_of_controls), after_controls_size_index + controls_size))
	}
	
	#[inline(always)]
	fn parse_controls_size(bLengthUsize: usize, entity_body: &[u8], after_sources_index: usize, minimum_b_length: usize) -> Result<usize, ExtensionUnitEntityParseError>
	{
		let bControlSize = entity_body.u8(entity_index_non_constant(after_sources_index));
		let controls_size = bControlSize as usize;
		if unlikely!(bLengthUsize < (minimum_b_length + controls_size))
		{
			return Err(ExtensionUnitEntityParseError::BLengthTooShortForControlSize { bLength: bLengthUsize as u8, bControlSize })
		}
		Ok(controls_size)
	}
}
