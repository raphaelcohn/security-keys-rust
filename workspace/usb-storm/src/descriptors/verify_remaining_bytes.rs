// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn verify_remaining_bytes<E, const MinimumBLength: u8>(remaining_bytes: &[u8], bLength: u8, b_length_is_less_than_minimum_error: E, b_length_exceeds_remining_bytes_error: E) -> Result<(&[u8], usize), E>
{
	if unlikely!(bLength < MinimumBLength)
	{
		return Err(b_length_is_less_than_minimum_error)
	}
	
	let available_descriptor_body_length = remaining_bytes.len();
	let stated_descriptor_body_length = reduce_b_length_to_descriptor_body_length(bLength);
	if unlikely!(stated_descriptor_body_length > available_descriptor_body_length)
	{
		return Err(b_length_exceeds_remining_bytes_error)
	}
	
	let descriptor_body_length = stated_descriptor_body_length;
	let descriptor_body = remaining_bytes.get_unchecked_range_safe(.. descriptor_body_length);
	Ok((descriptor_body, descriptor_body_length))
}
