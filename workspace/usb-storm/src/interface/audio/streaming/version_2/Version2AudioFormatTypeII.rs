// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format type II.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum Version2AudioFormatTypeII
{
	#[allow(missing_docs)]
	MPEG = 1 << 0,
	
	/// AC-3.
	AC_3 = 1 << 1,
	
	/// Windows Media Audio.
	WMA = 1 << 2,
	
	#[allow(missing_docs)]
	DTS = 1 << 3,
	
	#[allow(missing_docs)]
	RAW_DATA = 1 << 31,
}

impl Version2AudioFormatTypeII
{
	#[inline(always)]
	fn parse(formats_bit_map: u32) -> WrappedBitFlags<Self>
	{
		WrappedBitFlags::from_bits_truncate(formats_bit_map)
	}
}
