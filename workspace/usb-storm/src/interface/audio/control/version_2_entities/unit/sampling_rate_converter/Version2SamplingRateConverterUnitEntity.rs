// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A sampling rate unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2SamplingRateConverterUnitEntity
{
	description: Option<LocalizedStrings>,

	source_cluster_identifier: Option<UnitOrTerminalEntityIdentifier>,

	source_input_clock_entity: Option<ClockEntityIdentifier>,

	source_output_clock_entity: Option<ClockEntityIdentifier>,
}

impl Entity for Version2SamplingRateConverterUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version2SamplingRateConverterUnitEntityParseError::*;
		
		Ok
		(
			Alive
			(
				Self
				{
					source_cluster_identifier: entity_body.optional_non_zero_u8(entity_index::<4>()).map(UnitOrTerminalEntityIdentifier::new),
					
					source_input_clock_entity: entity_body.optional_non_zero_u8(entity_index::<5>()),
					
					source_output_clock_entity: entity_body.optional_non_zero_u8(entity_index::<6>()),
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(entity_index::<7>())).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version2SamplingRateConverterUnitEntity
{
}

impl Version2SamplingRateConverterUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn source_cluster_identifier(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.source_cluster_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn source_input_clock_entity(&self) -> Option<ClockEntityIdentifier>
	{
		self.source_input_clock_entity
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn source_output_clock_entity(&self) -> Option<ClockEntityIdentifier>
	{
		self.source_output_clock_entity
	}
}
