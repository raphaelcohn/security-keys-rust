// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait BytesExt: Bytes
{
	#[inline(always)]
	fn kilohertz(&self, index: usize) -> Kilohertz
	{
		self.u32(index)
	}
	
	#[inline(always)]
	fn baud(&self, index: usize) -> Baud
	{
		self.u32(index)
	}
}

impl<'a> BytesExt for &'a [u8]
{
}
