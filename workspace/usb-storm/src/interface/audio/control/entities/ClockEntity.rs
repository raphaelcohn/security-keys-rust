// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A clock entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum ClockEntity
{
	Source
	{
	},
	
	Selector
	{
	},
	
	Multiplier
	{
	},
}

impl Entity for ClockEntity
{
	type EntityIdentifier = ClockEntityIdentifier;
	
	#[inline(always)]
	fn cast_entity_identifier(value: Option<EntityIdentifier>) -> Option<Self::EntityIdentifier>
	{
		unsafe { transmute(value) }
	}
}

impl ClockEntity
{
	#[inline(always)]
	pub(super) fn parse_source(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			ClockEntity::Source
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_selector(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			ClockEntity::Selector
			{
			
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_multiplier(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok
		(
			ClockEntity::Multiplier
			{
			
			}
		)
	}
}
