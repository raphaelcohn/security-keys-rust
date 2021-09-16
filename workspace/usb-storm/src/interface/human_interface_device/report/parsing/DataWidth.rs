// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Width of data; important if a value might be a signed integer.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum DataWidth
{
	#[allow(missing_docs)]
	Widthless = 0,
	
	#[allow(missing_docs)]
	EightBit = 1,
	
	#[allow(missing_docs)]
	SixteenBit = 2,
	
	#[allow(missing_docs)]
	ThirtyTwoBit = 3,
}

impl Default for DataWidth
{
	#[inline(always)]
	fn default() -> Self
	{
		DataWidth::Widthless
	}
}
