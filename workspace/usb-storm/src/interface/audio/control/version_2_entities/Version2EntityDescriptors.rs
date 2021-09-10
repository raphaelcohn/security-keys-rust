// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entity descriptors.
#[derive(Default, Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2EntityDescriptors
{
	input_terminal: Entities<Version2InputTerminalEntity>,
	
	output_terminal: Entities<Version2OutputTerminalEntity>,
	
	mixer_unit: Entities<Version2MixerUnitEntity>,
	
	selector_unit: Entities<Version2SelectorUnitEntity>,
	
	feature_unit: Entities<Version2FeatureUnitEntity>,
	
	effect_unit: Entities<Version2EffectUnitEntity>,
	
	processing_unit: Entities<Version2ProcessingUnitEntity>,
	
	extension_unit: Entities<Version2ExtensionUnitEntity>,
	
	sampling_rate_converter_unit: Entities<Version2SamplingRateConverterUnitEntity>,
	
	source_clock: Entities<Version2SourceClockEntity>,
	
	selector_clock: Entities<Version2SelectorClockEntity>,
	
	multiplier_clock: Entities<Version2MultiplierClockEntity>,
}

impl EntityDescriptors for Version2EntityDescriptors
{
	type Error = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn parse_entity_body(&mut self, bLength: u8, bDescriptorSubType: u8, entity_identifier: Option<NonZeroU8>, entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<bool>, EntityDescriptorParseError<Self::Error>>
	{
		// These constants differ in value between versions 1, 2 and 3 of the Audio specifications!
		const INPUT_TERMINAL: u8 = 0x02;
		const OUTPUT_TERMINAL: u8 = 0x03;
		const MIXER_UNIT: u8 = 0x04;
		const SELECTOR_UNIT: u8 = 0x05;
		const FEATURE_UNIT: u8 = 0x06;
		const EFFECT_UNIT: u8 = 0x07;
		const PROCESSING_UNIT: u8 = 0x08;
		const EXTENSION_UNIT: u8 = 0x09;
		const CLOCK_SOURCE: u8 = 0x0A;
		const CLOCK_SELECTOR: u8 = 0x0B;
		const CLOCK_MULTIPLIER: u8 = 0x0C;
		const SAMPLE_RATE_CONVERTER: u8 = 0x0D;
		
		let dead_or_alive = match bDescriptorSubType
		{
			INPUT_TERMINAL => parse_entity_descriptor::<_, 17>(bLength, entity_identifier, entity_body, device_connection, &mut self.input_terminal)?,
			
			OUTPUT_TERMINAL => parse_entity_descriptor::<_, 12>(bLength, entity_identifier, entity_body, device_connection, &mut self.output_terminal)?,
			
			MIXER_UNIT =>
			{
				const MinimumBLength: u8 = Version2EntityDescriptors::MixerUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.mixer_unit)?
			}
			
			SELECTOR_UNIT =>
			{
				const MinimumBLength: u8 = Version2EntityDescriptors::SelectorUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.selector_unit)?
			}
			
			FEATURE_UNIT =>
			{
				const MinimumBLength: u8 = Version2EntityDescriptors::FeatureUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.feature_unit)?
			}
			
			EFFECT_UNIT =>
			{
				const MinimumBLength: u8 = Version2EntityDescriptors::EffectUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.effect_unit)?
			}
			
			PROCESSING_UNIT =>
			{
				const MinimumBLength: u8 = Version2EntityDescriptors::ProcessingUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.processing_unit)?
			}
			
			EXTENSION_UNIT =>
			{
				const MinimumBLength: u8 = Version2EntityDescriptors::ExtensionUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.extension_unit)?
			}
			
			CLOCK_SOURCE =>
			{
				parse_entity_descriptor::<_, 8>(bLength, entity_identifier, entity_body, device_connection, &mut self.source_clock)?
			}
			
			CLOCK_SELECTOR =>
			{
				const MinimumBLength: u8 = 7;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.selector_clock)?
			}
			
			CLOCK_MULTIPLIER =>
			{
				parse_entity_descriptor::<_, 7>(bLength, entity_identifier, entity_body, device_connection, &mut self.multiplier_clock)?
			}
			
			SAMPLE_RATE_CONVERTER =>
			{
				parse_entity_descriptor::<_, 8>(bLength, entity_identifier, entity_body, device_connection, &mut self.sampling_rate_converter_unit)?
			}
			
			_ => return Ok(Alive(false))
		};
		
		Ok(dead_or_alive.map(|()| true))
	}
}

impl Version2EntityDescriptors
{
	const MixerUnitMinimumBLength: u8 = 13;
	
	const SelectorUnitMinimumBLength: u8 = 7;
	
	const FeatureUnitMinimumBLength: u8 = 6;
	
	const EffectUnitMinimumBLength: u8 = 8;
	
	const ProcessingUnitMinimumBLength: u8 = 17;
	
	const ExtensionUnitMinimumBLength: u8 = 16;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_terminal(&self) -> &Entities<Version2InputTerminalEntity>
	{
		&self.input_terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn output_terminal(&self) -> &Entities<Version2OutputTerminalEntity>
	{
		&self.output_terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn mixer_unit(&self) -> &Entities<Version2MixerUnitEntity>
	{
		&self.mixer_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn selector_unit(&self) -> &Entities<Version2SelectorUnitEntity>
	{
		&self.selector_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn feature_unit(&self) -> &Entities<Version2FeatureUnitEntity>
	{
		&self.feature_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn processing_unit(&self) -> &Entities<Version2ProcessingUnitEntity>
	{
		&self.processing_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn extension_unit(&self) -> &Entities<Version2ExtensionUnitEntity>
	{
		&self.extension_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn sampling_rate_converter_unit(&self) -> &Entities<Version2SamplingRateConverterUnitEntity>
	{
		&self.sampling_rate_converter_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn source_clock(&self) -> &Entities<Version2SourceClockEntity>
	{
		&self.source_clock
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn selector_clock(&self) -> &Entities<Version2SelectorClockEntity>
	{
		&self.selector_clock
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn multiplier_clock(&self) -> &Entities<Version2MultiplierClockEntity>
	{
		&self.multiplier_clock
	}
}
