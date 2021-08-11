// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Channel feature control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u16)]
pub enum AudioChannelFeatureControl
{
	#[allow(missing_docs)]
	Mute = 0 << 1,
	
	#[allow(missing_docs)]
	Volume = 1 << 1,
	
	#[allow(missing_docs)]
	Bass = 1 << 2,
	
	#[allow(missing_docs)]
	Mid = 1 << 3,
	
	#[allow(missing_docs)]
	Treble = 1 << 4,
	
	#[allow(missing_docs)]
	GraphicEqualizer = 1 << 5,
	
	#[allow(missing_docs)]
	AutomaticGain = 1 << 6,
	
	#[allow(missing_docs)]
	Delay = 1 << 7,
	
	#[allow(missing_docs)]
	BassBoost = 1 << 8,
	
	#[allow(missing_docs)]
	Loudness = 1 << 9,
}
