// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entities.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Entities<E: Entity>
{
	identified: HashMap<E::EntityIdentifier, E>,
	
	undefined: Vec<E>,
}

impl<E: Entity> Default for Entities<E>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			identified: HashMap::new(),
			
			undefined: Vec::new(),
		}
	}
}

impl<E: Entity> Entities<E>
{
	#[inline(always)]
	fn push_unidentified(&mut self, entity: E) -> Result<(), EntityDescriptorParseError<E::ParseError>>
	{
		self.undefined.try_push(entity).map_err(EntityDescriptorParseError::OutOfMemoryPushingAnonymousEntityDescriptor)
	}
	
	#[inline(always)]
	fn push_identified(&mut self, entity: E, entity_identifier: E::EntityIdentifier)
	{
		let outcome = self.identified.insert(entity_identifier, entity);
		debug_assert!(outcome.is_none());
	}
}
