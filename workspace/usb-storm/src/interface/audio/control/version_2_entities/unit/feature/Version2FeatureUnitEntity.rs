// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A feature unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2FeatureUnitEntity
{
	input_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
	
	controls_by_channel_number: ChannelControlsByChannelNumber<Version2AudioChannelFeatureControls>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2FeatureUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version2FeatureUnitEntityParseError::*;
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_cluster: entity_body.optional_non_zero_u8(entity_index::<4>()).map(UnitOrTerminalEntityIdentifier::new),
					
					controls_by_channel_number: parse_controls_by_channel_number(entity_body, Version2AudioChannelFeatureControls::parse, ControlsLengthNotAMultipleOfFour, CouldNotAllocateMemoryForControls, |cause, channel_index| ChannelControlInvalid { cause, channel_index })?,
					
					description: return_ok_if_dead!(device_connection.find_string(entity_body.u8(entity_body.len() - 1)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version2FeatureUnitEntity
{
}

impl Version2FeatureUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.input_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn controls_by_channel_number(&self) -> &ChannelControlsByChannelNumber<Version2AudioChannelFeatureControls>
	{
		&self.controls_by_channel_number
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
}
