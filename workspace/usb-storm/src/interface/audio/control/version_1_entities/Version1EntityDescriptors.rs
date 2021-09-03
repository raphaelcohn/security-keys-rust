// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entity descriptors.
#[derive(Default, Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1EntityDescriptors
{
	input_terminal: Entities<Version1InputTerminalEntity>,
	
	output_terminal: Entities<Version1OutputTerminalEntity>,
	
	mixer_unit: Entities<Version1MixerUnitEntity>,
	
	selector_unit: Entities<Version1SelectorUnitEntity>,
	
	feature_unit: Entities<Version1FeatureUnitEntity>,
	
	processing_unit: Entities<Version1ProcessingUnitEntity>,
	
	extension_unit: Entities<Version1ExtensionUnitEntity>,
}

impl EntityDescriptors for Version1EntityDescriptors
{
	type Error = Version1EntityDescriptorParseError;
	
	#[inline(always)]
	fn parse_entity_body(&mut self, bLength: u8, bDescriptorSubtype: u8, entity_identifier: Option<NonZeroU8>, entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<bool>, EntityDescriptorParseError<Self::Error>>
	{
		// These constants differ in value between versions 1, 2 and 3 of the Audio specifications!
		const INPUT_TERMINAL: u8 = 0x02;
		const OUTPUT_TERMINAL: u8 = 0x03;
		const MIXER_UNIT: u8 = 0x04;
		const SELECTOR_UNIT: u8 = 0x05;
		const FEATURE_UNIT: u8 = 0x06;
		const PROCESSING_UNIT: u8 = 0x07;
		const EXTENSION_UNIT: u8 = 0x08;
		
		let dead_or_alive = match bDescriptorSubtype
		{
			INPUT_TERMINAL => parse_entity_descriptor::<_, 12>(bLength, entity_identifier, entity_body, device_connection, &mut self.input_terminal)?,
			
			OUTPUT_TERMINAL => parse_entity_descriptor::<_, 9>(bLength, entity_identifier, entity_body, device_connection, &mut self.output_terminal)?,
			
			MIXER_UNIT =>
			{
				const MinimumBLength: u8 = Version1EntityDescriptors::MixerUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.mixer_unit)?
			}
			
			SELECTOR_UNIT =>
			{
				const MinimumBLength: u8 = Version1EntityDescriptors::SelectorUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.selector_unit)?
			}
			
			FEATURE_UNIT =>
			{
				const MinimumBLength: u8 = Version1EntityDescriptors::FeatureUnitMinimumBLength;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.feature_unit)?
			}
			
			PROCESSING_UNIT =>
			{
				const MinimumBLength: u8 = 13;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.processing_unit)?
			}
			
			EXTENSION_UNIT =>
			{
				const MinimumBLength: u8 = 13;
				parse_entity_descriptor::<_, MinimumBLength>(bLength, entity_identifier, entity_body, device_connection, &mut self.extension_unit)?
			}
			
			_ => return Ok(Alive(false))
		};
		Ok(dead_or_alive.map(|()| true))
	}
}

impl Version1EntityDescriptors
{
	const MixerUnitMinimumBLength: u8 = 10;
	
	const SelectorUnitMinimumBLength: u8 = 6;
	
	const FeatureUnitMinimumBLength: u8 = 7;
}
