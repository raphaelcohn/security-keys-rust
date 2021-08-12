// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn parse_entity_descriptor<E: Entity, const BLength: u8>(string_finder: &StringFinder, entity_descriptors_bytes: &[u8], bLength: u8, entity_identifiers: &mut HashSet<EntityIdentifier>, entities: &mut Entities<E>) -> Result<DeadOrAlive<()>, EntityDescriptorParseError<E::ParseError>>
{
	use EntityDescriptorParseError::*;
	
	#[inline(always)]
	fn parse_entity_descriptor_body<E: Entity>(descriptor_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<E>, EntityDescriptorParseError<E::ParseError>>
	{
		E::parse(descriptor_body.get_unchecked_range_safe(DescriptorSubTypeAndEntityIdentifierLength .. ), string_finder).map_err(Version)
	}
	
	let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<EntityDescriptorParseError<E::ParseError>, BLength>(entity_descriptors_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
	
	let x = parse_entity_descriptor_body(entity_descriptors_bytes, string_finder)?;
	let entity = return_ok_if_dead!(x);
	
	match descriptor_body.optional_non_zero_u8_adjusted::<3>()
	{
		None => entities.push_anonymous(entity),
		
		Some(entity_identifier) =>
		{
			let inserted = entity_identifiers.insert(entity_identifier);
			if unlikely!(inserted == false)
			{
				return Err(DuplicateEntityIdentifier { entity_identifier })
			}
			
			entities.push_identified(entity, E::cast_entity_identifier(entity_identifier))
		}
	};
	
	Ok(Alive(()))
}
