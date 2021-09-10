// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Input terminal entity descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputTerminalEntity
{
	associated_output_terminal: Option<TerminalEntityIdentifier>,

	terminal_type: InputTerminalType,
	
	description: Option<LocalizedStrings>,
}

impl Entity for InputTerminalEntity
{
	type EntityIdentifier = TerminalEntityIdentifier;
	
	type ParseError = InputTerminalEntityParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], device_connection: &DeviceConnection, specification_version: Version) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use InputTerminalEntityParseError::*;
		
		if unlikely!(bLengthUsize < Self::MinimumBLength)
		{
			return Err(BLengthTooShort { bLength: bLengthUsize as u8 })
		}
		
		Ok
		(
			Alive
			(
				Self
				{
					associated_output_terminal: entity_body.optional_non_zero_u8(entity_index::<6>()),
					
					terminal_type: InputTerminalType::parse(bLengthUsize, entity_body, specification_version)?,
					
					description:
					{
						let dead_or_alive = device_connection.find_string(entity_body.u8(entity_index::<7>())).map_err(InvalidDescriptionString)?;
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

impl TerminalEntity for InputTerminalEntity
{
	type TerminalType = InputTerminalType;
	
	#[inline(always)]
	fn associated_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_output_terminal
	}
	
	#[inline(always)]
	fn terminal_type(&self) -> &Self::TerminalType
	{
		&self.terminal_type
	}
}

impl InputTerminalEntity
{
	const MinimumBLength: usize = InputSpecificTerminalType::MinimumBLength as usize;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn associated_output_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_output_terminal
	}
	
}
