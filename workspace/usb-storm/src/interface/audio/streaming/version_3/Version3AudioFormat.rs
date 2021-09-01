// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[bitflags]
#[serde(deny_unknown_fields)]
#[repr(u64)]
pub enum Version3AudioFormat
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
	DSD = 1 << 5,
	
	#[allow(missing_docs)]
	RAW_DATA = 1 << 6,
	
	#[allow(missing_docs)]
	PCM_IEC60958 = 1 << 7,
	
	#[allow(missing_docs)]
	AC_3 = 1 << 8,
	
	#[allow(missing_docs)]
	MPEG_1_Layer1 = 1 << 9,
	
	#[allow(missing_docs)]
	MPEG_1_Layer2_or_MPEG_1_Layer3_or_MPEG_2_NOEXT = 1 << 10,
	
	#[allow(missing_docs)]
	MPEG_2_EXT = 1 << 11,
	
	#[allow(missing_docs)]
	MPEG_2_AAC_ADTS = 1 << 12,
	
	#[allow(missing_docs)]
	MPEG_2_Layer1_LS = 1 << 13,
	
	#[allow(missing_docs)]
	MPEG_2_Layer2_LS_or_MPEG_Layer3_LS = 1 << 14,
	
	#[allow(missing_docs)]
	DTS_I = 1 << 15,
	
	#[allow(missing_docs)]
	DTS_II = 1 << 16,
	
	#[allow(missing_docs)]
	DTS_III = 1 << 17,
	
	#[allow(missing_docs)]
	ATRAC = 1 << 18,
	
	#[allow(missing_docs)]
	ATRAC2_or_ATRAC3 = 1 << 19,
	
	#[allow(missing_docs)]
	WMA = 1 << 20,
	
	#[allow(missing_docs)]
	E_AC_3 = 1 << 21,
	
	#[allow(missing_docs)]
	MAT = 1 << 22,
	
	#[allow(missing_docs)]
	DTS_IV = 1 << 23,
	
	#[allow(missing_docs)]
	MPEG_4_HE_AAC = 1 << 24,
	
	#[allow(missing_docs)]
	MPEG_4_HE_AAC_V2 = 1 << 25,
	
	#[allow(missing_docs)]
	MPEG_4_AAC_LC = 1 << 26,
	
	#[allow(missing_docs)]
	DRA = 1 << 27,
	
	#[allow(missing_docs)]
	MPEG_4_HE_AAC_SURROUND = 1 << 28,
	
	#[allow(missing_docs)]
	MPEG_4_AAC_LC_SURROUND = 1 << 29,
	
	#[allow(missing_docs)]
	MPEG_H_3D_AUDIO = 1 << 30,
	
	#[allow(missing_docs)]
	AC4 = 1 << 31,
	
	#[allow(missing_docs)]
	MPEG_4_AAC_ELD = 1 << 32,
}
