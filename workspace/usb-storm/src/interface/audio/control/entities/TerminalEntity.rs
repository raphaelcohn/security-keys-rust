// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum TerminalEntity
{
	Input
	{
		terminal_type: InputTerminalType,
	
		common: TerminalEntityCommon,
	},
	
	Output
	{
		terminal_type: OutputTerminalType,
		
		common: TerminalEntityCommon,
		
		unit_or_terminal_source: Option<UnitOrTerminalEntityIdentifier>,
	},
}

impl Entity for TerminalEntity
{
	type EntityIdentifier = TerminalEntityIdentifier;
	
	#[inline(always)]
	fn cast_entity_identifier(value: Option<EntityIdentifier>) -> Option<Self::EntityIdentifier>
	{
		unsafe { transmute(value) }
	}
}

impl TerminalEntity
{
	#[inline(always)]
	pub(super) fn parse_input(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			TerminalEntity::Input
			{
				terminal_type: InputTerminalType::parse(entity_body.u16_unadjusted(adjusted_index::<4>()))?,
				
				common: TerminalEntityCommon
				{
					associated_terminal: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<6>()),
					
					clock_source: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<7>()),
					
					controls: TerminalControls::new::<8>(entity_body),
					
					cluster_descriptor_identifier: entity_body.u16_unadjusted(adjusted_index::<12>()),
					
					extended_terminal_descriptor_identifier: entity_body.optional_non_zero_u16_unadjusted(adjusted_index::<14>()),
					
					connectors_descriptor_identifier: entity_body.optional_non_zero_u16_unadjusted(adjusted_index::<16>()),
					
					string_descriptor_identifier: Version3AudioDynamicStringDescriptorIdentifier::parse(entity_body, adjusted_index::<18>(), EntityDescriptorParseError::AudioDynamicStringDescriptorIdentifierIsOutOfRange)?,
				},
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_output(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			TerminalEntity::Output
			{
				terminal_type: OutputTerminalType::parse(entity_body.u16_unadjusted(adjusted_index::<4>()))?,
				
				common: TerminalEntityCommon
				{
					associated_terminal: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<7>()),
					
					clock_source: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<8>()),
					
					controls: TerminalControls::new::<9>(entity_body),
					
					cluster_descriptor_identifier: entity_body.u16_unadjusted(adjusted_index::<13>()),
					
					extended_terminal_descriptor_identifier: entity_body.optional_non_zero_u16_unadjusted(adjusted_index::<15>()),
					
					connectors_descriptor_identifier: entity_body.optional_non_zero_u16_unadjusted(adjusted_index::<17>()),
					
					string_descriptor_identifier: Version3AudioDynamicStringDescriptorIdentifier::parse(entity_body, adjusted_index::<19>(), EntityDescriptorParseError::AudioDynamicStringDescriptorIdentifierIsOutOfRange)?,
				},
				
				unit_or_terminal_source: entity_body.optional_non_zero_u8_unadjusted(adjusted_index::<7>()).map(UnitOrTerminalEntityIdentifier::new),
			}
		)
	}
}
