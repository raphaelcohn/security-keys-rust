// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2FeatureUnitEntityChannelControlParseError
{
	#[allow(missing_docs)]
	Mute,
	
	#[allow(missing_docs)]
	Volume,
	
	#[allow(missing_docs)]
	Bass,
	
	#[allow(missing_docs)]
	Mid,
	
	#[allow(missing_docs)]
	Treble,
	
	#[allow(missing_docs)]
	GraphicEqualizer,
	
	#[allow(missing_docs)]
	AutomaticGain,
	
	#[allow(missing_docs)]
	Delay,
	
	#[allow(missing_docs)]
	BassBoost,
	
	#[allow(missing_docs)]
	Loudness,
	
	#[allow(missing_docs)]
	InputGain,
	
	#[allow(missing_docs)]
	InputGainPad,
	
	#[allow(missing_docs)]
	PhaseInverter,
	
	#[allow(missing_docs)]
	Underflow,
	
	#[allow(missing_docs)]
	Overflow,
}

impl Display for Version2FeatureUnitEntityChannelControlParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2FeatureUnitEntityChannelControlParseError
{
}
