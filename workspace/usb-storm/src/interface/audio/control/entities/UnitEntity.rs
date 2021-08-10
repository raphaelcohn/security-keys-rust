// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum UnitEntity
{
	Mixer
	{
	},
	
	Selector
	{
	},
	
	Feature
	{
	},
	
	SampleRateConverter
	{
	},
	
	Effect
	{
	},
	
	Processing
	{
	},
	
	Extension
	{
	},
}

impl Entity for UnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	#[inline(always)]
	fn cast_entity_identifier(value: Option<EntityIdentifier>) -> Option<Self::EntityIdentifier>
	{
		unsafe { transmute(value) }
	}
}

impl UnitEntity
{
	#[inline(always)]
	pub(super) fn parse_mixer(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::Mixer
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_selector(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::Selector
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_feature(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::Feature
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_sample_rate_converter(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::SampleRateConverter
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_effect(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::Effect
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_processing(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::Processing
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_extension(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			UnitEntity::Extension
			{
			
			}
		)
	}
}
