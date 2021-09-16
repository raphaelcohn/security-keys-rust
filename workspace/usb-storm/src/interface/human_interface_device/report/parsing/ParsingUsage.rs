// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Usage.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct ParsingUsage
{
	page: Option<UsagePage>,

	identifier: u16,
}

impl PartialOrd for ParsingUsage
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		if unlikely!(self.page != other.page)
		{
			return None
		}
		Some(self.identifier.cmp(&other.identifier))
	}
}

impl ParsingUsage
{
	#[inline(always)]
	fn with_maximum(self, maximum: ParsingUsage) -> Result<ParsingUsageInclusiveRange, UsageParseError>
	{
		use UsageParseError::*;
		
		let minimum = self;
		use Ordering::Greater;
		match minimum.partial_cmp(&maximum)
		{
			None => Err(UsageMinimumAndUsageMaximumMustHaveSameUsagePage),
			
			Some(Greater) => Err(UsageMinimumMustBeLessThanMaximum),
			
			_ => Ok
			(
				ParsingUsageInclusiveRange
				{
					page: minimum.page,
				
					inclusive_minimum_identifier: minimum.identifier,
				
					inclusive_maximum_identifier: maximum.identifier,
				}
			),
		}
	}
	
	#[inline(always)]
	fn parse(data: u32, data_width: DataWidth, usage_page_can_not_be_zero_error: UsageParseError) -> Result<Self, UsageParseError>
	{
		Ok
		(
			Self
			{
				page: if data_width == DataWidth::ThirtyTwoBit
				{
					let usage_page_data = (data >> 16) as u16;
					if unlikely!(usage_page_data == 0)
					{
						return Err(usage_page_can_not_be_zero_error)
					}
					Some(UsagePage::new_checked(usage_page_data, usage_page_can_not_be_zero_error)?)
				}
				else
				{
					None
				},
			
				identifier: data as u16,
			}
		)
	}
}
