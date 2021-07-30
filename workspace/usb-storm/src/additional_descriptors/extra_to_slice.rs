// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn extra_to_slice<'a, E: error::Error>(extra: *const u8, extra_length: i32) -> Result<&'a [u8], AdditionalDescriptorParseError<E>>
{
	use AdditionalDescriptorParseError::*;
	
	if unlikely!(extra.is_null())
	{
		return Err(ExtraIsNull)
	}
	
	if unlikely!(extra_length < 0)
	{
		return Err(ExtraLengthIsNegative)
	}
	
	let extra_length = extra_length as usize;
	Ok(unsafe { from_raw_parts(extra, extra_length) })
}
