// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct ParsingUsagesLocalItems
{
	total_number_of_usages: usize,
	
	parsing_usage_inclusive_ranges: Vec<ParsingUsageInclusiveRange>,
	
	have_minimum_usage: Option<ParsingUsage>,
}

impl ParsingUsagesLocalItems
{
	#[inline(always)]
	fn finish_parsing(self, usage_page: ParsingUsagePage) -> Result<Vec<Usage>, LocalItemParseError>
	{
		use UsageParseError::*;

		if unlikely!(self.have_minimum_usage.is_some())
		{
			Err(UsageMinimumNotFollowedByUsageMaximum)?
		}
		
		let mut usages = Vec::new_with_capacity(self.total_number_of_usages).map_err(OutOfMemoryAllocatingUsages)?;
		for parsing_usage_inclusive_range in self.parsing_usage_inclusive_ranges
		{
			for usage in parsing_usage_inclusive_range.iter(usage_page)
			{
				usages.push_unchecked(usage);
			}
		}
		Ok(usages)
	}
	
	#[inline(always)]
	fn parse_usage(&mut self, data: u32, data_width: DataWidth) -> Result<(), LocalItemParseError>
	{
		use UsageParseError::*;
		
		let usage = ParsingUsage::parse(data, data_width, UsagePageCanNotBeZero)?;
		let parsing_usage_inclusive_range = usage.into();
		self.total_number_of_usages += 1;
		Ok(self.parsing_usage_inclusive_ranges.try_push(parsing_usage_inclusive_range).map_err(CouldNotPushUsageItem)?)
	}
	
	#[inline(always)]
	fn parse_usage_minimum(&mut self, minimum_data: u32, minimum_data_width: DataWidth) -> Result<(), LocalItemParseError>
	{
		use UsageParseError::*;
		
		if unlikely!(self.have_minimum_usage.is_some())
		{
			Err(UsageMinimumCanNotBeFollowedByUsageMinimum)?
		}
		self.have_minimum_usage = Some(ParsingUsage::parse(minimum_data, minimum_data_width, MinimumUsagePageCanNotBeZero)?);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_usage_maximum(&mut self, maximum_data: u32, maximum_data_width: DataWidth) -> Result<(), LocalItemParseError>
	{
		use UsageParseError::*;
		
		match self.have_minimum_usage.take()
		{
			None => Err(UsageMaximumMustBePreceededByUsageMinimum)?,
			
			Some(minimum) =>
			{
				let maximum = ParsingUsage::parse(maximum_data, maximum_data_width, MaximumUsagePageCanNotBeZero)?;
				let parsing_usage_inclusive_range = minimum.with_maximum(maximum)?;
				
				self.total_number_of_usages += parsing_usage_inclusive_range.len();
				self.parsing_usage_inclusive_ranges.try_push(parsing_usage_inclusive_range).map_err(CouldNotPushUsageItem)?;
			}
		}
		Ok(())
	}
}
