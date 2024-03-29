// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn parse_entity_descriptor<E: Entity, const MinimumBLength: u8>(bLength: u8, entity_identifier: Option<NonZeroU8>, entity_body: &[u8], device_connection: &DeviceConnection, entities: &mut Entities<E>) -> Result<DeadOrAlive<()>, EntityDescriptorParseError<E::ParseError>>
{
	use EntityDescriptorParseError::*;
	if unlikely!(bLength < MinimumBLength)
	{
		return Err(BLengthIsLessThanMinimum)
	}
	
	let dead_or_alive = E::parse(entity_body, device_connection).map_err(Version)?;
	let entity = return_ok_if_dead!(dead_or_alive);
	
	match entity_identifier
	{
		None => entities.push_anonymous(entity)?,
		
		Some(entity_identifier) =>
		{
			entities.push_identified(entity, entity_identifier)?
		}
	};
	
	Ok(Alive(()))
}
