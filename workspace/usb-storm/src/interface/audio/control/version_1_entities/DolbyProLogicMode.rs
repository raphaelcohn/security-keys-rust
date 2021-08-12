// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub enum DolbyProLogicMode
{
	/// Left-Right-Centre.
	LeftRightCentre = 0x0007,
	
	/// Left-Right-Surround.
	LeftRightSurround = 0x0103,
	
	/// Left-Right-Centre-Surround.
	LeftRightCentreSurround = 0x0107,
}

impl Into<BitFlags<Version1LogicalAudioChannelSpatialLocation>> for DolbyProLogicMode
{
	#[inline(always)]
	fn into(self) -> BitFlags<Version1LogicalAudioChannelSpatialLocation>
	{
		unsafe { BitFlags::from_bits_unchecked(self as u16) }
	}
}
