// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// More efficient that Rust's implementation.
#[inline(always)]
fn encode_utf8_raw(character: char, utf_8_bytes: &mut Vec<u8>)
{
	const TAG_CONT: u8 = 0b1000_0000;
	const TAG_TWO_B: u8 = 0b1100_0000;
	const TAG_THREE_B: u8 = 0b1110_0000;
	const TAG_FOUR_B: u8 = 0b1111_0000;
	
	let code = character as u32;
	if likely!(code < 0x80)
	{
		utf_8_bytes.push_unchecked(code as u8)
	}
	else if likely!(code < 0x800)
	{
		utf_8_bytes.push_unchecked((code >> 6 & 0x1F) as u8 | TAG_TWO_B);
		utf_8_bytes.push_unchecked((code & 0x3F) as u8 | TAG_CONT)
	}
	else if likely!(code < 0x10000)
	{
		utf_8_bytes.push_unchecked((code >> 12 & 0x0F) as u8 | TAG_THREE_B);
		utf_8_bytes.push_unchecked((code >> 6 & 0x3F) as u8 | TAG_CONT);
		utf_8_bytes.push_unchecked((code & 0x3F) as u8 | TAG_CONT);
	}
	else
	{
		utf_8_bytes.push_unchecked((code >> 18 & 0x07) as u8 | TAG_FOUR_B);
		utf_8_bytes.push_unchecked((code >> 12 & 0x3F) as u8 | TAG_CONT);
		utf_8_bytes.push_unchecked((code >> 6 & 0x3F) as u8 | TAG_CONT);
		utf_8_bytes.push_unchecked((code & 0x3F) as u8 | TAG_CONT);
	}
}
