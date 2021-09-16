// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum UsageParseError
{
	#[allow(missing_docs)]
	UsagePageCanNotBeZero,
	
	#[allow(missing_docs)]
	MinimumUsagePageCanNotBeZero,
	
	#[allow(missing_docs)]
	MaximumUsagePageCanNotBeZero,
	
	#[allow(missing_docs)]
	UsageMinimumCanNotBeFollowedByUsageMinimum,
	
	#[allow(missing_docs)]
	UsageMaximumMustBePreceededByUsageMinimum,
	
	#[allow(missing_docs)]
	UsageMinimumAndUsageMaximumMustHaveSameUsagePage,
	
	#[allow(missing_docs)]
	UsageMinimumMustBeLessThanMaximum,
	
	#[allow(missing_docs)]
	UsageMinimumNotFollowedByUsageMaximum,
	
	#[allow(missing_docs)]
	OutOfMemoryAllocatingUsages(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotPushUsageItem(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for UsageParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for UsageParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use UsageParseError::*;
		
		match self
		{
			OutOfMemoryAllocatingUsages(cause) => Some(cause),
			
			CouldNotPushUsageItem(cause) => Some(cause),
			
			_ => None,
		}
	}
}
