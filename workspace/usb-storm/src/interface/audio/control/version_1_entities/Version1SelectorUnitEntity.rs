// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A selector unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version1SelectorUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version1SelectorUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version1EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		use Version1EntityDescriptorParseError::*;
		
		let p = parse_p::<DescriptorEntityMinimumLength>(entity_body);
		
		if unlikely!(((Version1EntityDescriptors::SelectorUnitMinimumBLength as usize) + p) != (DescriptorEntityMinimumLength + entity_body.len()))
		{
			return Err(SelectorUnitLengthWrong)
		}
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::version_1_parse(p, entity_body, 5)?,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8_unadjusted(adjusted_index_non_constant(5 + p))).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version1SelectorUnitEntity
{
}

impl Version1SelectorUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_clusters(&self) -> &InputLogicalAudioChannelClusters
	{
		&self.input_logical_audio_channel_clusters
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}
