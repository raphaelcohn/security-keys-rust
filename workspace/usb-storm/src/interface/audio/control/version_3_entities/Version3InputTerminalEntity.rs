// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version3InputTerminalEntity
{
	input_terminal_type: InputTerminalType,
	
	associated_output_terminal: Option<TerminalEntityIdentifier>,
	
	common: TerminalEntityCommon,
}

impl Entity for Version3InputTerminalEntity
{
	type EntityIdentifier = TerminalEntityIdentifier;
	
	type ParseError = Version3EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], _device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version3EntityDescriptorParseError::*;
		
		Ok
		(
			Alive
			(
				Self
				{
					input_terminal_type: InputTerminalType::parse(entity_body.u16(entity_index::<4>()), TerminalTypeIsOutputOnly)?,
					
					associated_output_terminal: entity_body.optional_non_zero_u8(entity_index::<6>()),
					
					common: TerminalEntityCommon
					{
						clock_source: entity_body.optional_non_zero_u8(entity_index::<7>()),
						
						controls: TerminalControls::parse::<8>(entity_body)?,
						
						cluster_descriptor_identifier: entity_body.u16(entity_index::<12>()),
						
						extended_terminal_descriptor_identifier: entity_body.optional_non_zero_u16(entity_index::<14>()),
						
						connectors_descriptor_identifier: entity_body.optional_non_zero_u16(entity_index::<16>()),
						
						description: Version3AudioDynamicStringDescriptorIdentifier::parse(entity_body, entity_index::<18>(), AudioDynamicStringDescriptorIdentifierIsOutOfRange)?,
					},
				}
			)
		)
	}
}

impl Version3Entity for Version3InputTerminalEntity
{
}

impl TerminalEntity for Version3InputTerminalEntity
{
}

impl InputTerminalEntity for Version3InputTerminalEntity
{
	type LACC = ();
	
	#[inline(always)]
	fn input_terminal_type(&self) -> InputTerminalType
	{
		self.input_terminal_type
	}
	
	#[inline(always)]
	fn associated_output_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_output_terminal
	}
	
	#[inline(always)]
	fn output_logical_audio_channel_cluster(&self) -> &Self::LACC
	{
		unimplemented!()
	}
}

impl Version3TerminalEntity for Version3InputTerminalEntity
{
	#[inline(always)]
	fn common(&self) -> &TerminalEntityCommon
	{
		&self.common
	}
}
