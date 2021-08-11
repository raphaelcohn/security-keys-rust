// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An output terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version1OutputTerminalEntity
{
	output_terminal_type: OutputTerminalType,
	
	associated_input_terminal: Option<TerminalEntityIdentifier>,
	
	description: Option<LocalizedStrings>,
	
	output_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
}

impl Entity for Version1OutputTerminalEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version1EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version1EntityDescriptorParseError::*;
		
		Ok
		(
			Alive
			(
				Self
				{
					output_terminal_type: OutputTerminalType::parse(entity_body.u16_unadjusted(adjusted_index::<4>()))?,
					
					associated_input_terminal: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<6>()),
				
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8_unadjusted(adjusted_index::<8>())).map_err(InvalidDescriptionString)?),
					
					output_logical_audio_channel_cluster: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<7>()).map(UnitOrTerminalEntityIdentifier::new),
				}
			)
		)
	}
}

impl TerminalEntity for Version1OutputTerminalEntity
{
}

impl Version1OutputTerminalEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn output_terminal_type(&self) -> OutputTerminalType
	{
		self.output_terminal_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn associated_input_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_input_terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn output_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.output_logical_audio_channel_cluster
	}
}
