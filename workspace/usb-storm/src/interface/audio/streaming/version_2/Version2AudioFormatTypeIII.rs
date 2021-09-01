// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format type III (IEC 61937).
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum Version2AudioFormatTypeIII
{
	#[allow(missing_docs)]
	AC_3 = 1 << 0,
	
	#[allow(missing_docs)]
	MPEG_1_Layer1 = 1 << 1,
	
	#[allow(missing_docs)]
	MPEG_1_Layer2_or_MPEG_1_Layer3_or_MPEG_2_NOEXT = 1 << 2,
	
	#[allow(missing_docs)]
	MPEG_2_EXT = 1 << 3,
	
	#[allow(missing_docs)]
	MPEG_2_AAC_ADTS = 1 << 4,
	
	#[allow(missing_docs)]
	MPEG_2_Layer1_LS = 1 << 5,

	#[allow(missing_docs)]
	MPEG_2_Layer2_LS_or_MPEG_2_Layer3_LS = 1 << 6,

	#[allow(missing_docs)]
	DTS_I = 1 << 7,

	#[allow(missing_docs)]
	DTS_II = 1 << 8,

	#[allow(missing_docs)]
	DTS_III = 1 << 9,

	#[allow(missing_docs)]
	ATRAC = 1 << 10,

	#[allow(missing_docs)]
	ATRAC2_or_ATRAC3 = 1 << 11,

	/// Windows Media Audio.
	TYPE_III_WMA = 1 << 12,
}

impl Version2AudioFormatTypeIII
{
	#[inline(always)]
	fn parse(formats_bit_map: u32) -> WrappedBitFlags<Self>
	{
		WrappedBitFlags::from_bits_truncate(formats_bit_map)
	}
}
