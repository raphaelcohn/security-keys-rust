// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Dolby ProLogic mode.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub enum DolbyProLogicMode
{
	/// Left-Right-Center.
	LeftRightCenter = 0x0007,
	
	/// Left-Right-Surround.
	LeftRightSurround = 0x0103,
	
	/// Left-Right-Center-Surround.
	LeftRightCenterSurround = 0x0107,
}

impl Into<WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>> for DolbyProLogicMode
{
	#[inline(always)]
	fn into(self) -> WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>
	{
		WrappedBitFlags::from_bits_unchecked(self as u16)
	}
}

impl Into<WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>> for DolbyProLogicMode
{
	#[inline(always)]
	fn into(self) -> WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>
	{
		WrappedBitFlags::from_bits_unchecked(self as u32)
	}
}

impl TryFrom<WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>> for DolbyProLogicMode
{
	type Error = DolbyProLogicModeConversionError;
	
	#[inline(always)]
	fn from(value: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>) -> Result<Self, Self::Error>
	{
		use DolbyProLogicMode::*;
		
		let mode: u16 = value.into();
		match mode
		{
			0x0007 => Ok(LeftRightCenter),
			
			0x0103 => Ok(LeftRightSurround),
			
			0x0107 => Ok(LeftRightCenterSurround),
			
			_ => Err(DolbyProLogicModeConversionError { mode: value })
		}
	}
}

impl TryFrom<WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>> for DolbyProLogicMode
{
	type Error = DolbyProLogicModeConversionError;
	
	#[inline(always)]
	fn from(value: WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>) -> Result<Self, Self::Error>
	{
		use DolbyProLogicMode::*;
		
		let mode: u32 = value.into();
		match mode
		{
			0x0000_0007 => Ok(LeftRightCenter),
			
			0x0000_0103 => Ok(LeftRightSurround),
			
			0x0000_0107 => Ok(LeftRightCenterSurround),
			
			_ => Err(DolbyProLogicModeConversionError { mode: value })
		}
	}
}
