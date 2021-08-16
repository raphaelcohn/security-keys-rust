// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn validate_process_type_empty<E: error::Error>(process_type_specific_bytes: &[u8], p: usize, not_empty_error: E, not_exactly_one_pin_error: E) -> Result<(), E>
{
	if unlikely!(!process_type_specific_bytes.is_empty())
	{
		return Err(not_empty_error)
	}
	
	if unlikely!(p != 1)
	{
		return Err(not_exactly_one_pin_error)
	}
	
	Ok(())
}
