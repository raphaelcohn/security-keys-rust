// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An effect unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2EffectUnitEntity
{
	input_logical_audio_channel_cluster: Option<UnitOrTerminalEntityIdentifier>,
	
	controls_by_channel_number: ChannelControlsByChannelNumber<Version2AudioChannelEffectControls>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2EffectUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version2EffectUnitEntityParseError::*;
		use Version2EffectTypeParseError::*;
		
		const EFFECT_UNDEFINED: u16 = 0x00;
		const PARAM_EQ_SECTION_EFFECT: u16 = 0x01;
		const REVERBERATION_EFFECT: u16 = 0x02;
		const MOD_DELAY_EFFECT: u16 = 0x03;
		const DYN_RANGE_COMP_EFFECT: u16 = 0x04;
		
		let controls_by_channel_number = match entity_body.u16(entity_index::<4>())
		{
			EFFECT_UNDEFINED => parse_controls_by_channel_number(entity_body, Version2AudioChannelEffectControls::parse_undefined, ControlsLengthNotAMultipleOfFour, |cause, channel_index| ChannelControlInvalid { cause, channel_index }),
			
			PARAM_EQ_SECTION_EFFECT => parse_controls_by_channel_number(entity_body, Version2AudioChannelEffectControls::parse_parametric_equalizer_section, ControlsLengthNotAMultipleOfFour),
			
			REVERBERATION_EFFECT => parse_controls_by_channel_number(entity_body, Version2AudioChannelEffectControls::parse_reverberation, ControlsLengthNotAMultipleOfFour),
			
			MOD_DELAY_EFFECT => parse_controls_by_channel_number(entity_body, Version2AudioChannelEffectControls::parse_modulation_delay, ControlsLengthNotAMultipleOfFour),
			
			DYN_RANGE_COMP_EFFECT => parse_controls_by_channel_number(entity_body, Version2AudioChannelEffectControls::parse_dynamic_range_compressor, ControlsLengthNotAMultipleOfFour),
			
			effect_type @ _ => parse_controls_by_channel_number(entity_body, |controls| Version2AudioChannelEffectControls::parse_unrecognized(controls, new_non_zero_u16(effect_type)), ControlsLengthNotAMultipleOfFour),
		}?;
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_cluster: entity_body.optional_non_zero_u8(entity_index::<6>()).map(UnitOrTerminalEntityIdentifier::new),
					
					controls_by_channel_number,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(entity_body.len() - 1)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version2EffectUnitEntity
{
}

impl Version2EffectUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>
	{
		self.input_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn controls_by_channel_number(&self) -> &ChannelControlsByChannelNumber<Version2AudioChannelEffectControls>
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
