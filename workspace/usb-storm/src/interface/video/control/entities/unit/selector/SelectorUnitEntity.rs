// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Extension unit entity descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorUnitEntity
{
	sources: Sources,
	
	description: Option<LocalizedStrings>,
}

impl Entity for SelectorUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = SelectorUnitEntityParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], device_connection: &DeviceConnection, _specification_version: Version) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use SelectorUnitEntityParseError::*;
		
		if unlikely!(bLengthUsize < Self::MinimumBLength)
		{
			return Err(BLengthTooShort { bLength: bLengthUsize as u8 })
		}
		
		let (sources, after_sources_index) = Self::parse_sources(bLengthUsize, entity_body)?;
		Ok
		(
			Alive
			(
				Self
				{
					sources,
					
					description:
					{
						let dead_or_alive = device_connection.find_string(entity_body.u8(entity_index_non_constant(after_sources_index))).map_err(InvalidDescriptionString)?;
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

impl UnitEntity for SelectorUnitEntity
{
}

impl WithSourcesUnitEntity for SelectorUnitEntity
{
	#[inline(always)]
	fn sources(&self) -> &Sources
	{
		&self.sources
	}
}

impl SelectorUnitEntity
{
	const MinimumBLength: usize = 6;
	
	#[inline(always)]
	fn parse_sources(bLengthUsize: usize, entity_body: &[u8]) -> Result<(Sources, usize), SelectorUnitEntityParseError>
	{
		const MinimumBLength: usize = SelectorUnitEntity::MinimumBLength;
		let (sources, after_sources_index, _minimum_b_length) = Sources::parse::<MinimumBLength, 4>(bLengthUsize, entity_body)?;
		Ok((sources, after_sources_index))
	}
}
