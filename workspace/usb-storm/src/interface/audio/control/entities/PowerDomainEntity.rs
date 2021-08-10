// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A power domain entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct PowerDomainEntity;

impl Entity for PowerDomainEntity
{
	type EntityIdentifier = PowerDomainEntityIdentifier;
	
	#[inline(always)]
	fn cast_entity_identifier(value: Option<EntityIdentifier>) -> Option<Self::EntityIdentifier>
	{
		unsafe { transmute(value) }
	}
}

impl PowerDomainEntity
{
	#[inline(always)]
	pub(super) fn parse_power_domain(entity_body: &[u8]) -> Result<Self, EntityDescriptorParseError>
	{
		Ok(Self)
	}
}
