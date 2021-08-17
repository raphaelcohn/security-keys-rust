// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn parse_entity_descriptor<E: Entity, const MinimumBLength: u8>(string_finder: &StringFinder, entity_descriptors_bytes: &[u8], bLength: u8, entities: &mut Entities<E>) -> Result<DeadOrAlive<()>, EntityDescriptorParseError<E::ParseError>>
{
	use EntityDescriptorParseError::*;
	
	let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<EntityDescriptorParseError<E::ParseError>, MinimumBLength>(entity_descriptors_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
	
	let x = E::parse(descriptor_body.get_unchecked_range_safe(DescriptorSubTypeAndEntityIdentifierLength .. ), string_finder).map_err(Version)?;
	let entity = return_ok_if_dead!(x);
	
	match descriptor_body.optional_non_zero_u8(adjust_descriptor_index::<3>())
	{
		None => entities.push_anonymous(entity)?,
		
		Some(entity_identifier) =>
		{
			entities.push_identified(entity, entity_identifier)?
		}
	};
	
	Ok(Alive(()))
}
