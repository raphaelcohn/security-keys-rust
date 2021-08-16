// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Dolby ProLogic conversion error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DolbyProLogicModeConversionError<LACSL: LogicalAudioChannelSpatialLocation>
{
	mode: WrappedBitFlags<LACSL>
}

impl<LACSL: LogicalAudioChannelSpatialLocation> Display for DolbyProLogicModeConversionError<LACSL>
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl<LACSL: LogicalAudioChannelSpatialLocation> error::Error for DolbyProLogicModeConversionError<LACSL>
{
}
