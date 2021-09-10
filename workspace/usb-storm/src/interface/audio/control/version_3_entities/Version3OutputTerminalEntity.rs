// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An output terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version3OutputTerminalEntity
{
	output_terminal_type: OutputTerminalType,
	
	associated_input_terminal: Option<TerminalEntityIdentifier>,
	
	common: TerminalEntityCommon,
	
	output_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
}

impl Entity for Version3OutputTerminalEntity
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
					output_terminal_type: OutputTerminalType::parse(entity_body.u16(entity_index::<4>()), TerminalTypeIsInputOnly)?,
					
					associated_input_terminal: entity_body.optional_non_zero_u8(entity_index::<7>()),
					
					common: TerminalEntityCommon
					{
						
						clock_source: entity_body.optional_non_zero_u8(entity_index::<8>()),
						
						controls: TerminalControls::parse::<9>(entity_body)?,
						
						cluster_descriptor_identifier: entity_body.u16(entity_index::<13>()),
						
						extended_terminal_descriptor_identifier: entity_body.optional_non_zero_u16(entity_index::<15>()),
						
						connectors_descriptor_identifier: entity_body.optional_non_zero_u16(entity_index::<17>()),
						
						description: Version3AudioDynamicStringDescriptorIdentifier::parse(entity_body, entity_index::<19>(), AudioDynamicStringDescriptorIdentifierIsOutOfRange)?,
					},
					
					output_logical_audio_channel_cluster: entity_body.optional_non_zero_u8(entity_index::<7>()).map(UnitOrTerminalEntityIdentifier::new),
				}
			)
		)
	}
}

impl Version3Entity for Version3OutputTerminalEntity
{
}

impl TerminalEntity for Version3OutputTerminalEntity
{
}

impl OutputTerminalEntity for Version3OutputTerminalEntity
{
	#[allow(missing_docs)]
	fn output_terminal_type(&self) -> OutputTerminalType
	{
		self.output_terminal_type
	}
	
	#[allow(missing_docs)]
	fn associated_input_terminal(&self) -> Option<TerminalEntityIdentifier>
	{
		self.associated_input_terminal
	}
	
	#[allow(missing_docs)]
	fn output_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.output_logical_audio_channel_cluster
	}
}

impl Version3TerminalEntity for Version3OutputTerminalEntity
{
	#[inline(always)]
	fn common(&self) -> &TerminalEntityCommon
	{
		&self.common
	}
}
