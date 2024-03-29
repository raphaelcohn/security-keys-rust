// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Automatic parameters features.
///
/// Strictly speaking, only one of `AutomaticParametersNegotiationMadeByTheCcid` or `AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters` is supposed to be present, but the Yubico 5 seems to specify both.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum AutomaticParametersFeature
{
	/// Use of warm or cold resets or PPS according to a manufacturer proprietary algorithm to select the communication parameters with the ICC.
	#[allow(dead_code)]
	AutomaticParametersNegotiationMadeByTheCcid = 0x0000_0040,
	
	#[allow(missing_docs)]
	#[allow(dead_code)]
	AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters = 0x0000_0080,
}

impl AutomaticParametersFeature
{
	#[inline(always)]
	fn parse(dwFeatures: u32) -> WrappedBitFlags<Self>
	{
		WrappedBitFlags::from_bits_truncate(dwFeatures)
	}
}
