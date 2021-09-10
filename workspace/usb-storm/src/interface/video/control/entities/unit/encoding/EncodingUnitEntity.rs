// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Encoding unit entity descriptor.
///
/// Only exists for specification version 1.5+.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncodingUnitEntity
{
	source: Option<EntityIdentifier>,
	
	initialization_controls: WrappedBitFlags<EncodingControl>,
	
	runtime_controls: WrappedBitFlags<EncodingControl>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for EncodingUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = EncodingUnitEntityParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], device_connection: &DeviceConnection, _specification_version: Version) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use EncodingUnitEntityParseError::*;
		
		if unlikely!(bLengthUsize < Self::MinimumBLength)
		{
			return Err(BLengthTooShort { bLength: bLengthUsize as u8 })
		}
		
		{
			let bControlSize = entity_body.u8(entity_index::<6>());
			if unlikely!(bControlSize != 3)
			{
				return Err(ControlSizeIsNot3 { bControlSize })
			}
		}
		
		Ok
		(
			Alive
			(
				Self
				{
					source: entity_body.optional_non_zero_u8(entity_index::<4>()),
					
					initialization_controls: Self::parse_controls::<7>(entity_body),
					
					runtime_controls: Self::parse_controls::<10>(entity_body),
					
					description:
					{
						let dead_or_alive = device_connection.find_string(entity_body.u8(entity_index::<5>())).map_err(InvalidDescriptionString)?;
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

impl WithSourceEntity for EncodingUnitEntity
{
	#[inline(always)]
	fn source(&self) -> Option<EntityIdentifier>
	{
		self.source
	}
}

impl UnitEntity for EncodingUnitEntity
{
}

impl EncodingUnitEntity
{
	const MinimumBLength: usize = 13;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn initialization_controls(&self) -> WrappedBitFlags<EncodingControl>
	{
		self.initialization_controls
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn runtime_controls(&self) -> WrappedBitFlags<EncodingControl>
	{
		self.runtime_controls
	}
	
	#[inline(always)]
	fn parse_controls<const index: usize>(entity_body: &[u8]) -> WrappedBitFlags<EncodingControl>
	{
		WrappedBitFlags::from_bits_truncate(entity_body.u24_as_u32(entity_index::<index>()))
	}
}
