// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
struct ParsingUsageInclusiveRange
{
	page: Option<UsagePage>,

	inclusive_minimum_identifier: UsageIdentifier,

	inclusive_maximum_identifier: UsageIdentifier,
}

impl TryClone for ParsingUsageInclusiveRange
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(*self)
	}
}

impl From<ParsingUsage> for ParsingUsageInclusiveRange
{
	#[inline(always)]
	fn from(value: ParsingUsage) -> ParsingUsageInclusiveRange
	{
		Self
		{
			page: value.page,
			
			inclusive_minimum_identifier: value.identifier,
			
			inclusive_maximum_identifier: value.identifier
		}
	}
}

impl ParsingUsageInclusiveRange
{
	#[inline(always)]
	fn len(&self) -> usize
	{
		((self.inclusive_maximum_identifier - self.inclusive_minimum_identifier) as usize) + 1
	}
	
	#[inline(always)]
	fn iter(self, usage_page: UsagePage) -> ParsingUsageInclusiveRangeIterator
	{
		ParsingUsageInclusiveRangeIterator
		{
			page: match self.page
			{
				None => usage_page,
				
				Some(page) => page,
			},
			
			identifiers: self.inclusive_minimum_identifier ..= self.inclusive_maximum_identifier,
		}
	}
}
