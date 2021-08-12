// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// LCD layout.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LcdLayout
{
	number_of_lines: u8,
	
	number_of_characters_per_line: u8,
}

impl LcdLayout
{
	#[inline(always)]
	fn from(value: u16) -> Option<Self>
	{
		if likely!(value == 0x0000)
		{
			None
		}
		else
		{
			Some
			(
				Self
				{
					number_of_lines: ((value >> 8) as u8),
					
					number_of_characters_per_line: (value & 0xFF) as u8
				}
			)
		}
	}
}
