// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ReaderNames<'buffer>(&'buffer [u8]);

impl<'buffer> Iterator for ReaderNames<'buffer>
{
	type Item = &'buffer CStr;
	
	#[inline(always)]
	fn next(&mut self) -> Option<Self::Item>
	{
		let null_index = memchr(0x00, self.0).expect("The final item is an empty string");
		if null_index == 0
		{
			return None
		}
		let item = self.0.get_unchecked_range_safe(0 .. null_index);
		self.0 = self.0.get_unchecked_range_safe((null_index + 1) .. );
		Some(unsafe { CStr::from_bytes_with_nul_unchecked(item) })
	}
	
	#[inline(always)]
	fn size_hint(&self) -> (usize, Option<usize>)
	{
		if unlikely!(self.len() == 1)
		{
			(0, Some(0))
		}
		else
		{
			(1, None)
		}
	}
}
