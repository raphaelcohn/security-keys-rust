// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn parse_control_size(entity_body: &[u8], index: usize, error: Version1EntityDescriptorParseError) -> Result<NonZeroUsize, Version1EntityDescriptorParseError>
{
	let bControlSize = entity_body.u8(entity_index_non_constant(index));
	if bControlSize == 0
	{
		return Err(error)
	}
	Ok(new_non_zero_usize(bControlSize as usize))
}
