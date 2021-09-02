// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamplingFrequencyParseError
{
	#[allow(missing_docs)]
	ContinuousSamplingFrequencyBLengthWrong
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	ContinuousSamplingFrequencyLengthWrong
	{
		length: usize,
	},
	
	#[allow(missing_docs)]
	ContinuousSamplingFrequencyBoundsNegative
	{
		lower_bound: Hertz,
		
		upper_bound: Hertz,
	},
	
	#[allow(missing_docs)]
	DiscreteSamplingFrequencyBLengthWrong
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	DiscreteSamplingFrequencyLengthWrong
	{
		length: usize,
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForDiscreteSamplingFrequencies(TryReserveError),
}

impl Display for SamplingFrequencyParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SamplingFrequencyParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SamplingFrequencyParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForDiscreteSamplingFrequencies(cause) => Some(cause),
			
			_ => None,
		}
	}
}
