// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Channel spatial location.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum Version2LogicalAudioChannelSpatialLocation
{
	/// `FL`.
	FrontLeft = 1 << 0,
	
	/// `FR`.
	FrontRight = 1 << 1,
	
	/// `FC`.
	FrontCenter = 1 << 2,
	
	/// `LFE`.
	LowFrequencyEffects = 1 << 3,
	
	/// `BL`.
	BackLeft = 1 << 4,
	
	/// `BR`.
	BackRight = 1 << 5,
	
	/// `FLC`.
	FrontLeftOfCenter = 1 << 6,
	
	/// `FRC`.
	FrontRightOfCenter = 1 << 7,
	
	/// `BC`.
	BackCenter = 1 << 8,
	
	/// `SL`.
	SideLeft = 1 << 9,
	
	/// `SR`.
	SideRight = 1 << 10,
	
	/// `TC`.
	TopCenter = 1 << 11,
	
	/// `TFL`.
	TopFrontLeft = 1 << 12,
	
	/// `TFC`.
	TopFrontCenter = 1 << 13,
	
	/// `TFR`.
	TopFrontRight = 1 << 14,
	
	/// `TBL`.
	TopBackLeft = 1 << 15,
	
	/// `TBC`.
	TopBackCenter = 1 << 16,
	
	/// `TBR`.
	TopBackRight = 1 << 17,
	
	/// `TFLC`.
	TopFrontLeftOfCenter = 1 << 18,
	
	/// `TFRC`.
	TopFrontRightOfCenter = 1 << 19,
	
	/// `LLFE`.
	LeftLowFrequencyEffects = 1 << 20,
	
	/// `RLFE`.
	RightLowFrequencyEffects = 1 << 21,
	
	/// `TSL`.
	TopSideLeft = 1 << 22,
	
	/// `TSR`.
	TopSideRight = 1 << 23,
	
	/// `BC`.
	BottomCenter = 1 << 24,
	
	/// `BLC`.
	BackLeftOfCenter = 1 << 25,
	
	/// `BRC`.
	BackRightOfCenter = 1 << 26,
	
	/// Reserved.
	Reserved27 = 1 << 27,
	
	/// Reserved.
	Reserved28 = 1 << 28,
	
	/// Reserved.
	Reserved29 = 1 << 29,
	
	/// Reserved.
	Reserved30 = 1 << 30,
}

impl LogicalAudioChannelSpatialLocation for Version2LogicalAudioChannelSpatialLocation
{
}
