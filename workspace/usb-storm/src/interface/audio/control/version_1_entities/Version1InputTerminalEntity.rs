// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1InputTerminalEntity
{
	input_terminal_type: InputTerminalType,
	
	associated_output_terminal: Option<TerminalEntityIdentifier>,
	
	input_logical_audio_channel_cluster: Version1LogicalAudioChannelCluster,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version1InputTerminalEntity
{
	type EntityIdentifier = TerminalEntityIdentifier;
	
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
					input_terminal_type: InputTerminalType::parse(entity_body.u16_unadjusted(adjusted_index::<4>())).map_err(InputTerminalTypeParse)?,
					
					associated_output_terminal: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<6>()),
					
					input_logical_audio_channel_cluster: return_ok_if_dead!(Version1LogicalAudioChannelCluster::parse(7, string_finder, entity_body)?),
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8_unadjusted(adjusted_index::<11>())).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl TerminalEntity for Version1InputTerminalEntity
{
}

impl Version1InputTerminalEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_terminal_type(&self) -> InputTerminalType
	{
		self.input_terminal_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn associated_output_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_output_terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_logical_audio_channel_cluster(&self) -> &Version1LogicalAudioChannelCluster
	{
		&self.input_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}
