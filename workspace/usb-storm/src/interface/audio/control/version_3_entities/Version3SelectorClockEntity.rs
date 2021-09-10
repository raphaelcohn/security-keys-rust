// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A selector clock entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version3SelectorClockEntity;

impl Entity for Version3SelectorClockEntity
{
	type EntityIdentifier = ClockEntityIdentifier;
	
	type ParseError = Version3EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(_entity_body: &[u8], _device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		Ok(Alive(Self))
	}
}

impl Version3Entity for Version3SelectorClockEntity
{
}

impl ClockEntity for Version3SelectorClockEntity
{
}

impl SelectorClockEntity for Version3SelectorClockEntity
{
}
