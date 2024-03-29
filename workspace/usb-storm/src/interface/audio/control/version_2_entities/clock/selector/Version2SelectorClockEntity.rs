// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A selector clock entity.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2SelectorClockEntity
{
	description: Option<LocalizedStrings>,
	
	sources: Vec<Option<ClockEntityIdentifier>>,
	
	selector: Control,
}

impl Entity for Version2SelectorClockEntity
{
	type EntityIdentifier = ClockEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version2SelectorClockEntityParseError::*;
		
		let p = parse_p::<DescriptorEntityMinimumLength>(entity_body);
		
		let sources_size: usize =
		{
			const PSize: usize = 1;
			const ClusterIdentifierSize: usize = 1;
			PSize + (p * ClusterIdentifierSize)
		};
		const ControlsSize: usize = 1;
		const StringDescriptorSize: usize = 1;
		
		let required_size = sources_size + ControlsSize + StringDescriptorSize;
		if unlikely!(required_size > entity_body.len())
		{
			Err(PIsTooLarge)?
		}
		
		let bmControls = entity_body.u8(entity_index_non_constant(DescriptorEntityMinimumLength + sources_size));
		
		Ok
		(
			Alive
			(
				Self
				{
					selector: Control::parse_u8(bmControls, 0, SelectorControlInvalid)?,
					
					sources: Vec::new_populated(p, CouldNotAllocateSources, |index|
					{
						Ok(entity_body.optional_non_zero_u8(entity_index_non_constant(5 + index)))
					})?,
					
					description: return_ok_if_dead!(device_connection.find_string(entity_body.u8(entity_body.len() - 1)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl DescribedEntity for Version2SelectorClockEntity
{
	#[inline(always)]
	fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}

impl Version2Entity for Version2SelectorClockEntity
{
}

impl ClockEntity for Version2SelectorClockEntity
{
}

impl SelectorClockEntity for Version2SelectorClockEntity
{
}

impl Version2SelectorClockEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn selector(&self) -> Control
	{
		self.selector
	}
}
