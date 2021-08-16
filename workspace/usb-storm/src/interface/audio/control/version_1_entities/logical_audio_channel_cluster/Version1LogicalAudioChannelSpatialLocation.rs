// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Channel spatial location.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u16)]
pub enum Version1LogicalAudioChannelSpatialLocation
{
	/// `L`.
	LeftFront = 1 << 0,
	
	/// `R`.
	RightFront = 1 << 1,
	
	/// `C`.
	CenterFront = 1 << 2,
	
	/// `LFE`.
	LowFrequencyEnhancement = 1 << 3,
	
	/// `Ls`.
	LeftSurround = 1 << 4,
	
	/// `Rs`.
	RightSurround = 1 << 5,
	
	/// `Lc`.
	LeftOfCenter = 1 << 6,
	
	/// `Rc`.
	RightOfCenter = 1 << 7,
	
	/// `S`.
	Surround = 1 << 8,
	
	/// `Sl`.
	SideLeft = 1 << 9,
	
	/// `Sr`.
	SideRight = 1 << 10,
	
	/// `T`.
	Top = 1 << 11,

	/// Reserved.
	Reserved12 = 1 << 12,
	
	/// Reserved.
	Reserved13 = 1 << 13,
	
	/// Reserved.
	Reserved14 = 1 << 14,
	
	/// Reserved.
	Reserved15 = 1 << 15,
}

impl LogicalAudioChannelSpatialLocation for Version1LogicalAudioChannelSpatialLocation
{
	#[inline(always)]
	fn parse_mode_bit_map(process_type_specific_bytes: &[u8], index: usize) -> Self::Numeric
	{
		process_type_specific_bytes.u16(index)
	}
}
