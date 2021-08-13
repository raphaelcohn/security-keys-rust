// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A selector clock entity.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2SourceClockEntity
{
	clock_type: ClockType,
	
	synchronized_to_sof: bool,
	
	frequency: Control,
	
	validity: Control,
	
	associated_terminal: Option<TerminalEntityIdentifier>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2SourceClockEntity
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
		use Version2EntityDescriptorParseError::*;
		
		let bmAttributes = entity_body.u8(entity_index::<4>());
		let bmControls = entity_body.u8(entity_index::<5>());
		
		Ok
		(
			Alive
			(
				Self
				{
					clock_type: unsafe { transmute(bmAttributes & 0b11) },
					
					synchronized_to_sof: bmAttributes & 0b100 != 0,
					
					frequency: Control::parse_u8(bmControls, 0, SourceClockFrequencyControlInvalid)?,
					
					validity: Control::parse_u8(bmControls, 1, SourceClockValidityControlInvalid)?,
					
					associated_terminal: entity_body.optional_non_zero_u8(entity_index::<6>()),
					
					description:
					{
						let description = string_finder.find_string(entity_body.u8(entity_index::<7>())).map_err(InvalidDescriptionString)?;
						return_ok_if_dead!(description)
					},
				}
			)
		)
	}
}

impl ClockEntity for Version2SourceClockEntity
{
}

impl Version2SourceClockEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn clock_type(&self) -> ClockType
	{
		self.clock_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn synchronized_to_sof(&self) -> bool
	{
		self.synchronized_to_sof
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn frequency(&self) -> Control
	{
		self.frequency
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn validity(&self) -> Control
	{
		self.validity
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn associated_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_terminal
	}
}
