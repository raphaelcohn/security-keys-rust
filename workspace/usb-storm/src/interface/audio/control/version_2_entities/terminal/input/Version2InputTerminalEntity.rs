// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2InputTerminalEntity
{
	input_terminal_type: InputTerminalType,
	
	associated_output_terminal: Option<TerminalEntityIdentifier>,
	
	clock_source: Option<ClockEntityIdentifier>,
	
	output_logical_audio_channel_cluster: Version2LogicalAudioChannelCluster,
	
	copy_protect_control: Control,
	
	connector_control: Control,
	
	overload_control: Control,
	
	cluster_control: Control,
	
	underflow_control: Control,
	
	overflow_control: Control,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2InputTerminalEntity
{
	type EntityIdentifier = TerminalEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		Ok(Self::parse_inner(entity_body, string_finder)?)
	}
}

impl TerminalEntity for Version2InputTerminalEntity
{
}

impl Version2InputTerminalEntity
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
	pub const fn clock_source(&self) -> Option<ClockEntityIdentifier>
	{
		self.clock_source
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
	pub const fn cluster_control(&self) -> Control
	{
		self.cluster_control
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
	pub const fn output_logical_audio_channel_cluster(&self) -> &Version2LogicalAudioChannelCluster
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
	fn parse_inner(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Version2InputTerminalEntityParseError>
	{
		use Version2InputTerminalEntityParseError::*;
		
		let bmControls = entity_body.u16(entity_index::<14>());
		
		Ok
		(
			Alive
			(
				Self
				{
					input_terminal_type: InputTerminalType::parse(entity_body.u16(entity_index::<4>()), TerminalTypeIsOutputOnly)?,
					
					associated_output_terminal: entity_body.optional_non_zero_u8(entity_index::<6>()),
					
					clock_source: entity_body.optional_non_zero_u8(entity_index::<7>()),
					
					output_logical_audio_channel_cluster: return_ok_if_dead!(Version2LogicalAudioChannelCluster::parse_entity(8, string_finder, entity_body)?),
					
					copy_protect_control: Control::parse_u16(bmControls, 0, CopyProtectControlInvalid)?,
					
					connector_control: Control::parse_u16(bmControls, 1, ConnectorControlInvalid)?,
					
					overload_control: Control::parse_u16(bmControls, 2, OverloadControlInvalid)?,
					
					cluster_control: Control::parse_u16(bmControls, 3, ClusterControlInvalid)?,
					
					underflow_control: Control::parse_u16(bmControls, 4, UnderflowControlInvalid)?,
					
					overflow_control: Control::parse_u16(bmControls, 5, OverflowControlInvalid)?,
					
					description:
					{
						let description = string_finder.find_string(entity_body.u8(entity_index::<16>())).map_err(InvalidDescriptionString)?;
						return_ok_if_dead!(description)
					},
				}
			)
		)
	}
}
