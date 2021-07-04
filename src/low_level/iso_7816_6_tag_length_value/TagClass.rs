// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
enum TagClass
{
	Universal = 0b00,
	
	Application = 0b01,
	
	ContextSpecific = 0b10,
	
	Private = 0b11,
}

impl TagClass
{
	#[inline(always)]
	const fn parse(leading_tag_byte: u8) -> Self
	{
		unsafe { transmute(leading_tag_byte >> 6) }
	}
}
