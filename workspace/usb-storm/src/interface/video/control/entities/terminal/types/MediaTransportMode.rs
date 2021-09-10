// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Media transport mode.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum MediaTransportMode
{
	#[allow(missing_docs)]
	PlayForward = 1 << 0,
	
	#[allow(missing_docs)]
	Pause = 1 << 1,
	
	#[allow(missing_docs)]
	Rewind = 1 << 2,
	
	#[allow(missing_docs)]
	FastForward = 1 << 3,
	
	#[allow(missing_docs)]
	HighSpeedRewind = 1 << 4,
	
	#[allow(missing_docs)]
	Stop = 1 << 5,
	
	#[allow(missing_docs)]
	Eject = 1 << 6,
	
	#[allow(missing_docs)]
	PlayNextFrame = 1 << 7,
	
	#[allow(missing_docs)]
	PlaySlowestForward = 1 << 8,
	
	#[allow(missing_docs)]
	PlaySlowestForward4 = 1 << 9,
	
	#[allow(missing_docs)]
	PlaySlowestForward3 = 1 << 10,
	
	#[allow(missing_docs)]
	PlaySlowestForward2 = 1 << 11,
	
	#[allow(missing_docs)]
	PlaySlowestForward1 = 1 << 12,
	
	#[allow(missing_docs)]
	PlayX1 = 1 << 13,
	
	#[allow(missing_docs)]
	PlayFastForward1 = 1 << 14,
	
	#[allow(missing_docs)]
	PlayFastForward2 = 1 << 15,
	
	#[allow(missing_docs)]
	PlayFastForward3 = 1 << 16,
	
	#[allow(missing_docs)]
	PlayFastForward4 = 1 << 17,
	
	#[allow(missing_docs)]
	PlayFastestForward = 1 << 18,
	
	#[allow(missing_docs)]
	PlayPreviousFrame = 1 << 19,
	
	#[allow(missing_docs)]
	PlaySlowestReverse = 1 << 20,
	
	#[allow(missing_docs)]
	PlaySlowReverse4 = 1 << 21,
	
	#[allow(missing_docs)]
	PlaySlowReverse3 = 1 << 22,
	
	#[allow(missing_docs)]
	PlaySlowReverse2 = 1 << 23,
	
	#[allow(missing_docs)]
	PlaySlowReverse1 = 1 << 24,
	
	#[allow(missing_docs)]
	PlayX1Reverse = 1 << 25,
	
	#[allow(missing_docs)]
	PlayFastReverse1 = 1 << 26,
	
	#[allow(missing_docs)]
	PlayFastReverse2 = 1 << 27,
	
	#[allow(missing_docs)]
	PlayFastReverse3 = 1 << 28,
	
	#[allow(missing_docs)]
	PlayFastReverse4 = 1 << 29,
	
	#[allow(missing_docs)]
	PlayFastestReverse = 1 << 30,
	
	#[allow(missing_docs)]
	RecordStateStart = 1 << 31,
	
	#[allow(missing_docs)]
	RecordPause = 1 << 32,
	
	#[allow(missing_docs)]
	ReversePause = 1 << 33,
}
