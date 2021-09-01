// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Frequency range.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrequencyRange
{
	inclusive_lower_bound: Hertz,
	
	inclusive_upper_bound: Hertz,
}

impl FrequencyRange
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn inclusive_lower_bound(self) -> u32
	{
		self.inclusive_lower_bound
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn inclusive_upper_bound(self) -> u32
	{
		self.inclusive_upper_bound
	}
	
	#[inline(always)]
	fn parse(bLength: u8, remaining_bytes: &[u8]) -> Result<Self, ValidSamplingFrequencyRangeParseError>
	{
		use ValidSamplingFrequencyRangeParseError::*;
		
		const BLength: u8 = 11;
		let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<ValidSamplingFrequencyRangeParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let dMin = descriptor_body.u32(3);
		let dMax = descriptor_body.u32(7);
		if unlikely!(dMin > dMax)
		{
			return Err(MinimumGreaterThanMaximum{ dMin, dMax})
		}
		
		Ok
		(
			Self
			{
				inclusive_lower_bound: dMin,
				
				inclusive_upper_bound: dMax,
			}
		)
	}
}
