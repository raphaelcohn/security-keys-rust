// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format type IV.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum Version2AudioFormatTypeIV
{
	#[allow(missing_docs)]
	PCM = 1 << 0,
	
	#[allow(missing_docs)]
	PCM8 = 1 << 1,
	
	#[allow(missing_docs)]
	IEEE_FLOAT = 1 << 2,
	
	#[allow(missing_docs)]
	ALAW = 1 << 3,
	
	#[allow(missing_docs)]
	MULAW = 1 << 4,
	
	#[allow(missing_docs)]
	MPEG = 1 << 5,
	
	/// AC-3.
	AC_3 = 1 << 6,
	
	/// WMA.
	WMA = 1 << 7,
	
	#[allow(missing_docs)]
	IEC61937_AC_3 = 1 << 8,
	
	#[allow(missing_docs)]
	IEC61937_MPEG_1_Layer1 = 1 << 9,
	
	#[allow(missing_docs)]
	IEC61937_MPEG_1_Layer2_or_IEC61937_MPEG_1_Layer3_or_IEC61937_MPEG_2_NOEXT = 1 << 10,
	
	#[allow(missing_docs)]
	IEC61937_MPEG_2_EXT = 1 << 11,
	
	#[allow(missing_docs)]
	IEC61937_MPEG_2_AAC_ADTS = 1 << 12,
	
	#[allow(missing_docs)]
	IEC61937_MPEG_2_Layer1_LS = 1 << 13,
	
	#[allow(missing_docs)]
	IEC61937_MPEG_2_Layer2_LS_or_IEC61937_MPEG_2_Layer3_LS = 1 << 14,
	
	#[allow(missing_docs)]
	IEC61937_DTS_I = 1 << 15,
	
	#[allow(missing_docs)]
	IEC61937_DTS_II = 1 << 16,
	
	#[allow(missing_docs)]
	IEC61937_DTS_III = 1 << 17,
	
	#[allow(missing_docs)]
	IEC61937_ATRAC = 1 << 18,
	
	#[allow(missing_docs)]
	IEC61937_ATRAC2_or_IEC61937_ATRAC3 = 1 << 19,
	
	/// Windows Media Audio.
	IEC61937_TYPE_III_WMA = 1 << 20,
	
	#[allow(missing_docs)]
	IEC60958_PCM = 1 << 21,
}

impl Version2AudioFormatTypeIV
{
	#[inline(always)]
	fn parse(formats_bit_map: u32) -> WrappedBitFlags<Self>
	{
		WrappedBitFlags::from_bits_truncate(formats_bit_map)
	}
}
