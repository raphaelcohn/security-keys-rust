// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An output terminal entity.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2OutputTerminalEntity
{
	output_terminal_type: OutputTerminalType,
	
	associated_input_terminal: Option<TerminalEntityIdentifier>,
	
	clock_source: Option<ClockEntityIdentifier>,
	
	output_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
	
	copy_protect_control: Control,
	
	connector_control: Control,
	
	overload_control: Control,
	
	underflow_control: Control,
	
	overflow_control: Control,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2OutputTerminalEntity
{
	type EntityIdentifier = TerminalEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version2OutputTerminalEntityParseError::*;
		
		let bmControls = entity_body.u16(entity_index::<9>());
		
		Ok
		(
			Alive
			(
				Self
				{
					output_terminal_type: OutputTerminalType::parse(entity_body.u16(entity_index::<4>()), TerminalTypeIsInputOnly)?,
					
					associated_input_terminal: entity_body.optional_non_zero_u8(entity_index::<6>()),
					
					output_logical_audio_channel_cluster: entity_body.optional_non_zero_u8(entity_index::<7>()).map(UnitOrTerminalEntityIdentifier::new),
					
					clock_source: entity_body.optional_non_zero_u8(entity_index::<8>()),
					
					copy_protect_control: Control::parse_u16(bmControls, 0, CopyProtectControlInvalid)?,
					
					connector_control: Control::parse_u16(bmControls, 1, ConnectorControlInvalid)?,
					
					overload_control: Control::parse_u16(bmControls, 2, OverloadControlInvalid)?,
					
					underflow_control: Control::parse_u16(bmControls, 4, UnderflowControlInvalid)?,
					
					overflow_control: Control::parse_u16(bmControls, 5, OverflowControlInvalid)?,
					
					description:
					{
						let description = device_connection.find_string(entity_body.u8(entity_index::<11>())).map_err(InvalidDescriptionString)?;
						return_ok_if_dead!(description)
					},
				}
			)
		)
	}
}

impl TerminalEntity for Version2OutputTerminalEntity
{
}

impl Version2OutputTerminalEntity
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
	pub const fn clock_source(&self) -> Option<ClockEntityIdentifier>
	{
		self.clock_source
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn output_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.output_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn copy_protect_control(&self) -> Control
	{
		self.copy_protect_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn connector_control(&self) -> Control
	{
		self.connector_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overload_control(&self) -> Control
	{
		self.overload_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn underflow_control(&self) -> Control
	{
		self.underflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overflow_control(&self) -> Control
	{
		self.overflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}
