// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReverberationControlsParseError
{
	#[allow(missing_docs)]
	Enable,
	
	#[allow(missing_docs)]
	Type,
	
	#[allow(missing_docs)]
	Level,
	
	#[allow(missing_docs)]
	Time,
	
	#[allow(missing_docs)]
	DelayFeedback,
	
	#[allow(missing_docs)]
	PreDelay,
	
	#[allow(missing_docs)]
	Density,
	
	#[allow(missing_docs)]
	HighFrequencyRollOff,
	
	#[allow(missing_docs)]
	Underflow,
	
	#[allow(missing_docs)]
	Overflow,
}

impl Display for ReverberationControlsParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ReverberationControlsParseError
{
}
