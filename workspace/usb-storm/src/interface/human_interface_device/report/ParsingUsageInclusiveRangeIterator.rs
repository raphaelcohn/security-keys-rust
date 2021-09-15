// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ParsingUsageInclusiveRangeIterator
{
	page: UsagePage,
	
	identifiers: RangeInclusive<UsageIdentifier>,
}

impl Iterator for ParsingUsageInclusiveRangeIterator
{
	type Item = Usage;
	
	#[inline(always)]
	fn next(&mut self) -> Option<Self::Item>
	{
		self.identifiers.next().map(|identifier| Usage { page: self.page, identifier })
	}
	
	#[inline(always)]
	fn size_hint(&self) -> (usize, Option<usize>)
	{
		self.identifiers.size_hint()
	}
}

impl FusedIterator for ParsingUsageInclusiveRangeIterator
{
}

impl ExactSizeIterator for ParsingUsageInclusiveRangeIterator
{
	#[inline(always)]
	fn len(&self) -> usize
	{
		self.identifiers.len()
	}
}
