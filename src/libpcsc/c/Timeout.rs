// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum Timeout
{
	Immediate,

	/// A value of u32::MAX is not valid.
	Milliseconds(NonZeroU32),
	
	Infinity,
}

impl Default for Timeout
{
	#[inline(always)]
	fn default() -> Self
	{
		Timeout::Immediate
	}
}

impl Timeout
{
	#[inline(always)]
	fn into_DWORD(self) -> DWORD
	{
		use self::Timeout::*;
		
		match self
		{
			Immediate => 0,
			
			Milliseconds(milliseconds) =>
			{
				let milliseconds = milliseconds.get() as DWORD;
				assert_ne!(milliseconds, INFINITE);
				milliseconds
			}
			
			Infinity => INFINITE
		}
	}
}
