// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entity descriptors.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version3EntityDescriptors
{
	input_terminal: Entities<Version3InputTerminalEntity>,
	
	output_terminal: Entities<Version3OutputTerminalEntity>,
	
	mixer_unit: Entities<Version3MixerUnitEntity>,
	
	selector_unit: Entities<Version3SelectorUnitEntity>,
	
	feature_unit: Entities<Version3FeatureUnitEntity>,
	
	effect_unit: Entities<Version3EffectUnitEntity>,
	
	processing_unit: Entities<Version3ProcessingUnitEntity>,
	
	extension_unit: Entities<Version3ExtensionUnitEntity>,
	
	sample_rate_converter_unit: Entities<Version3SampleRateConverterUnitEntity>,
	
	source_clock: Entities<Version3SourceClockEntity>,
	
	selector_clock: Entities<Version3SelectorClockEntity>,
	
	multiplier_clock: Entities<Version3MultiplierClockEntity>,
	
	power_domain: Entities<Version3PowerDomainEntity>,
}

impl EntityDescriptors for Version3EntityDescriptors
{
	type Error = Version3EntityDescriptorParseError;
	
	#[inline(always)]
	fn parse_entity_body(&mut self, bDescriptorSubtype: u8, string_finder: &StringFinder, entity_descriptors_bytes: &[u8], bLength: u8, entity_identifiers: &mut HashSet<EntityIdentifier>) -> Result<DeadOrAlive<bool>, EntityDescriptorParseError<Self::Error>>
	{
		use EntityDescriptorParseError::Version;
		use Version3EntityDescriptorParseError::*;
		
		// These constants differ in value between versions 1, 2 and 3 of the Audio specifications!
		const INPUT_TERMINAL: u8 = 0x02;
		const OUTPUT_TERMINAL: u8 = 0x03;
		const EXTENDED_TERMINAL: u8 = 0x04;
		const MIXER_UNIT: u8 = 0x05;
		const SELECTOR_UNIT: u8 = 0x06;
		const FEATURE_UNIT: u8 = 0x07;
		const EFFECT_UNIT: u8 = 0x08;
		const PROCESSING_UNIT: u8 = 0x09;
		const EXTENSION_UNIT: u8 = 0x0A;
		const CLOCK_SOURCE: u8 = 0x0B;
		const CLOCK_SELECTOR: u8 = 0x0C;
		const CLOCK_MULTIPLIER: u8 = 0x0D;
		const SAMPLE_RATE_CONVERTER: u8 = 0x0E;
		const CONNECTORS: u8 = 0x0F;
		const POWER_DOMAIN: u8 = 0x10;
		
		let dead_or_alive = match bDescriptorSubtype
		{
			INPUT_TERMINAL => parse_entity_descriptor::<_, 20>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.input_terminal)?,
			
			OUTPUT_TERMINAL => parse_entity_descriptor::<_, 19>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.output_terminal)?,
			
			EXTENDED_TERMINAL => return Err(Version(ExtendedTerminalIsAHighCapacityDescriptor)),
			
			MIXER_UNIT =>
			{
				const MinimumBLength: u8 = 13;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.mixer_unit)?
			}
			
			SELECTOR_UNIT =>
			{
				const MinimumBLength: u8 = 11;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.selector_unit)?
			}
			
			FEATURE_UNIT =>
			{
				const MinimumBLength: u8 = 7;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.feature_unit)?
			}
			
			SAMPLE_RATE_CONVERTER => parse_entity_descriptor::<_, 9>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.sample_rate_converter_unit)?,
			
			CONNECTORS => return Err(Version(ConnectorsIsAHighCapacityDescriptor)),
			
			EFFECT_UNIT =>
			{
				const MinimumBLength: u8 = 9;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.effect_unit)?;
			}
			
			PROCESSING_UNIT =>
			{
				const MinimumBLength: u8 = 9;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.processing_unit)?;
			}
			
			EXTENSION_UNIT =>
			{
				const MinimumBLength: u8 = 15;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.extension_unit)?;
			}
			
			CLOCK_SOURCE => parse_entity_descriptor::<_, 12>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.source_clock)?,
			
			CLOCK_SELECTOR =>
			{
				const MinimumBLength: u8 = 11;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.selector_clock)?;
			}
			
			CLOCK_MULTIPLIER => parse_entity_descriptor::<_, 11>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.multiplier_clock)?,
			
			POWER_DOMAIN =>
			{
				const MinimumBLength: u8 = 11;
				parse_entity_descriptor::<_, MinimumBLength>(string_finder, entity_descriptors_bytes, bLength, &mut entity_identifiers, &mut self.power_domain)?
			}
			
			_ => return Ok(Alive(false))
		};
		
		Ok(dead_or_alive.map(|()| true))
	}
}

impl Version3EntityDescriptors
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_terminal(&self) -> &Entities<Version3InputTerminalEntity>
	{
		&self.input_terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn output_terminal(&self) -> &Entities<Version3OutputTerminalEntity>
	{
		&self.output_terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn mixer_unit(&self) -> &Entities<Version3MixerUnitEntity>
	{
		&self.mixer_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn selector_unit(&self) -> &Entities<Version3SelectorUnitEntity>
	{
		&self.selector_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn feature_unit(&self) -> &Entities<Version3FeatureUnitEntity>
	{
		&self.feature_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn processing_unit(&self) -> &Entities<Version3ProcessingUnitEntity>
	{
		&self.processing_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn extension_unit(&self) -> &Entities<Version3ExtensionUnitEntity>
	{
		&self.extension_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn sample_rate_converter_unit(&self) -> &Entities<Version3SampleRateConverterUnitEntity>
	{
		&self.sample_rate_converter_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn source_clock(&self) -> &Entities<Version3SourceClockEntity>
	{
		&self.source_clock
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn selector_clock(&self) -> &Entities<Version3SelectorClockEntity>
	{
		&self.selector_clock
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn multiplier_clock(&self) -> &Entities<Version3MultiplierClockEntity>
	{
		&self.multiplier_clock
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn power_domain(&self) -> &Entities<Version3PowerDomainEntity>
	{
		&self.power_domain
	}
}
