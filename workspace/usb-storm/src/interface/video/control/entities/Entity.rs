// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An entity.
pub trait Entity: Debug + Clone + Eq + Ord + Hash
{
	#[doc(hidden)]
	type EntityIdentifier: Debug + Copy + Eq + Ord + Hash + DeserializeOwned + Serialize;
	
	#[doc(hidden)]
	type ParseError: error::Error + Into<EntityDescriptorParseError>;
	
	#[doc(hidden)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier;
	
	#[doc(hidden)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], device_connection: &DeviceConnection, specification_version: Version) -> Result<DeadOrAlive<Self>, Self::ParseError>;
	
	#[allow(missing_docs)]
	fn description(&self) -> Option<&LocalizedStrings>;
}
