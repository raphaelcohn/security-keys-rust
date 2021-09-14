// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
const fn parse_exponent_nibble(exponent_nibble: u4) -> i8
{
	// From -8 to 7 inclusive, where 0x0 is 0, 0x7 (0b0000_1111) is 7, 0x8 is -8 and 0xF is -1.
	let exponent = if exponent_nibble <= 0b0000_1111
	{
		exponent_nibble
	}
	else
	{
		0b1111_0000 | exponent_nibble
	};
	exponent as i8
}
