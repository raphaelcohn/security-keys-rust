// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entity descriptors.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version3EntityDescriptors
{
	clock: Entities<ClockEntity>,
	
	power_domain: Entities<PowerDomainEntity>,
	
	terminal: Entities<TerminalEntity>,
	
	unit: Entities<UnitEntity>,
}

impl Version3EntityDescriptors
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn clock(&self) -> &Entities<ClockEntity>
	{
		&self.clock
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn power_domain(&self) -> &Entities<PowerDomainEntity>
	{
		&self.power_domain
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn terminal(&self) -> &Entities<TerminalEntity>
	{
		&self.terminal
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn unit(&self) -> &Entities<UnitEntity>
	{
		&self.unit
	}
	
	const DescriptorSubTypeAndEntityIdentifierLength: usize = 1 + 1;
	
	const MinimumLength: usize = DescriptorHeaderLength + Self::DescriptorSubTypeAndEntityIdentifierLength;
	
	#[inline(always)]
	pub(super) fn parse_entity_descriptors_version_3(mut entity_descriptors: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		use EntityDescriptorParseError::*;
		
		// These constants differ in value between versions 1, 2 and 3 of the Audio specifications!
		const AC_DESCRIPTOR_UNDEFINED: u8 = 0x00;
		const HEADER: u8 = 0x01;
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
		
		let mut this = Self::default();
		while !entity_descriptors.is_empty()
		{
			if unlikely!(entity_descriptors.len() < Self::MinimumLength)
			{
				return Err(LessThanFourByteHeader)
			}
			
			let bDescriptorType = entity_descriptors.u8_unadjusted(1);
			if unlikely!(bDescriptorType != AudioControlInterfaceAdditionalDescriptorParser::CS_INTERFACE)
			{
				return Err(ExpectedInterfaceDescriptorType)
			}
			
			let bLength = entity_descriptors.u8_unadjusted(0);
			let bDescriptorSubtype = entity_descriptors.u8_unadjusted(2);
			match bDescriptorSubtype
			{
				AC_DESCRIPTOR_UNDEFINED => return Err(UndefinedInterfaceDescriptorType),
				
				HEADER => return Err(HeaderInterfaceDescriptorTypeAfterHeader),
				
				INPUT_TERMINAL => Self::parse_entity_descriptor::<TerminalEntity, _, 20>(entity_descriptors, bLength, &mut this.terminal, TerminalEntity::parse_input)?,
				
				OUTPUT_TERMINAL => Self::parse_entity_descriptor::<TerminalEntity, _, 19>(entity_descriptors, bLength, &mut this.terminal, TerminalEntity::parse_output)?,
				
				EXTENDED_TERMINAL => return Err(ExtendedTerminalIsAHighCapacityDescriptor),
				
				MIXER_UNIT =>
				{
					const MinimumBLength: u8 = 13;
					Self::parse_entity_descriptor::<UnitEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_mixer)?
				}
				
				SELECTOR_UNIT =>
				{
					const MinimumBLength: u8 = 11;
					Self::parse_entity_descriptor::<UnitEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_selector)?
				}
				
				FEATURE_UNIT =>
				{
					const MinimumBLength: u8 = 7;
					Self::parse_entity_descriptor::<UnitEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_feature)?
				}
				
				SAMPLE_RATE_CONVERTER => Self::parse_entity_descriptor::<UnitEntity, _, 9>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_sample_rate_converter)?,
				
				CONNECTORS => return Err(ConnectorsIsAHighCapacityDescriptor),
				
				EFFECT_UNIT =>
				{
					const MinimumBLength: u8 = 9;
					Self::parse_entity_descriptor::<UnitEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_effect)?;
				}
				
				PROCESSING_UNIT =>
				{
					const MinimumBLength: u8 = 9;
					Self::parse_entity_descriptor::<UnitEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_processing)?;
				}
				
				EXTENSION_UNIT =>
				{
					const MinimumBLength: u8 = 15;
					Self::parse_entity_descriptor::<UnitEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.unit, UnitEntity::parse_extension)?;
				}
				
				CLOCK_SOURCE => Self::parse_entity_descriptor::<ClockEntity, _, 12>(entity_descriptors, bLength, &mut this.clock, ClockEntity::parse_source)?,
				
				CLOCK_SELECTOR =>
				{
					const MinimumBLength: u8 = 11;
					Self::parse_entity_descriptor::<ClockEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.clock, ClockEntity::parse_selector)?;
				}
				
				CLOCK_MULTIPLIER => Self::parse_entity_descriptor::<ClockEntity, _, 11>(entity_descriptors, bLength, &mut this.clock, ClockEntity::parse_multiplier)?,
				
				POWER_DOMAIN =>
				{
					const MinimumBLength: u8 = 11;
					Self::parse_entity_descriptor::<PowerDomainEntity, _, MinimumBLength>(entity_descriptors, bLength, &mut this.power_domain, PowerDomainEntity::parse_power_domain)?
				}
				
				_ => return Err(UnrecognizedEntityDescriptorType)
			};
			
			entity_descriptors = entity_descriptors.get_unchecked_range_safe((bLength as usize) .. );
		}
		
		Ok(this)
	}
	
	#[inline(always)]
	fn parse_entity_descriptor<E: Entity, EDBP: FnOnce(&[u8]) -> Result<E, EntityDescriptorParseError>, const BLength: u8>(entity_descriptors: &[u8], bLength: u8, entities: &mut Entities<E>, entity_descriptor_body_parser: EDBP) -> Result<(), EntityDescriptorParseError>
	{
		use EntityDescriptorParseError::*;
		
		let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<EntityDescriptorParseError, BLength>(entity_descriptors, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		let entity_identifier = E::cast_entity_identifier(descriptor_body.optional_non_zero_u8_adjusted::<3>());
		let entity = entity_descriptor_body_parser(descriptor_body.get_unchecked_range_safe(Self::DescriptorSubTypeAndEntityIdentifierLength .. ))?;
		entities.push(entity_identifier, entity)?;
		Ok(())
	}
}
