// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A multiplier clock entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2MultiplierClockEntity
{
	description: Option<LocalizedStrings>,
	
	source: Option<ClockEntityIdentifier>,
	
	numerator: Control,
	
	denominator: Control,
}

impl Entity for Version2MultiplierClockEntity
{
	type EntityIdentifier = ClockEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version2MultiplierClockEntityParseError::*;
		
		let bmControls = entity_body.u8(entity_index::<5>());
		
		Ok
		(
			Alive
			(
				Self
				{
					source: entity_body.optional_non_zero_u8(entity_index::<4>()),
					
					numerator: Control::parse_u8(bmControls, 0, NumeratorControlInvalid)?,
					
					denominator: Control::parse_u8(bmControls, 1, DenominatorControlInvalid)?,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(entity_index::<7>())).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl ClockEntity for Version2MultiplierClockEntity
{
}

impl Version2MultiplierClockEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	/// Clock Entity to which the last Clock Input Pin of this Clock Selector Entity is connected.
	#[inline(always)]
	pub const fn source(&self) -> Option<ClockEntityIdentifier>
	{
		self.source
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn numerator(&self) -> Control
	{
		self.numerator
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn denominator(&self) -> Control
	{
		self.denominator
	}
	
}
