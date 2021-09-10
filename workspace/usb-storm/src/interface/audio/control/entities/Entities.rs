// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entities.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord,  Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Entities<E: Entity>
{
	identified: WrappedHashMap<E::EntityIdentifier, E>,
	
	anonymous: Vec<E>,
}

impl<E: Entity> Default for Entities<E>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			identified: WrappedHashMap::empty(),
			
			anonymous: Vec::new(),
		}
	}
}

impl<E: Entity> Entities<E>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn identified(&self) -> &WrappedHashMap<E::EntityIdentifier, E>
	{
		&self.identified
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn anonymous(&self) -> &[E]
	{
		&self.anonymous
	}
	
	#[inline(always)]
	pub(crate) fn push_anonymous(&mut self, entity: E) -> Result<(), EntityDescriptorParseError<E::ParseError>>
	{
		self.anonymous.try_push(entity).map_err(EntityDescriptorParseError::OutOfMemoryPushingAnonymousEntityDescriptor)
	}
	
	#[inline(always)]
	pub(crate) fn push_identified(&mut self, entity: E, entity_identifier: NonZeroU8) -> Result<(), EntityDescriptorParseError<E::ParseError>>
	{
		use EntityDescriptorParseError::*;
		
		let outcome = self.identified.try_to_insert(E::cast_entity_identifier(entity_identifier), entity).map_err(OutOfMemoryPushingIdentifiedEntityDescriptor)?;
		if unlikely!(outcome.is_some())
		{
			return Err(DuplicateEntityIdentifier { entity_identifier })
		}
		Ok(())
	}
}
