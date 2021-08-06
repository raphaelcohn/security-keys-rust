// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait BytesExt: Bytes
{
	#[inline(always)]
	fn kilohertz<const index: usize>(&self) -> Kilohertz
	{
		self.u32_adjusted::<index>()
	}
	
	#[inline(always)]
	fn baud<const index: usize>(&self) -> Baud
	{
		self.u32_adjusted::<index>()
	}
}

impl<'a> BytesExt for &'a [u8]
{
}
