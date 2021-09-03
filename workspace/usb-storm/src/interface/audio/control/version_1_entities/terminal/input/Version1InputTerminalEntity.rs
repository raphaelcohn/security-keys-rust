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
	
	output_logical_audio_channel_cluster: Version1LogicalAudioChannelCluster,
	
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
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		Ok(Self::parse_inner(entity_body, device_connection)?)
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
	pub const fn output_logical_audio_channel_cluster(&self) -> &Version1LogicalAudioChannelCluster
	{
		&self.output_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse_inner(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Version1InputTerminalEntityParseError>
	{
		use Version1InputTerminalEntityParseError::*;
		
		let input_terminal_type = InputTerminalType::parse(entity_body.u16(entity_index::<4>()), TerminalTypeIsOutputOnly)?;
		let associated_output_terminal = entity_body.optional_non_zero_u8(entity_index::<6>());
		let description = return_ok_if_dead!(device_connection.find_string(entity_body.u8(entity_index::<11>())).map_err(InvalidDescriptionString)?);
		
		Ok
		(
			Alive
			(
				Self
				{
					input_terminal_type,
					
					associated_output_terminal,
					
					output_logical_audio_channel_cluster: return_ok_if_dead!(Version1LogicalAudioChannelCluster::parse(7, device_connection, entity_body)?),
					
					description,
				}
			)
		)
	}
}
