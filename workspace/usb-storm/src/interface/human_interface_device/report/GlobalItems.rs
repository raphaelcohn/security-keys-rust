// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A set of global items.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GlobalItems
{
	usage_page: Option<UsagePage>,
	
	logical_minimum_extent: Option<u32>,
	
	logical_maximum_extent: Option<u32>,
	
	physical_minimum_extent: Option<u32>,
	
	physical_maximum_extent: Option<u32>,
	
	unit_exponent: Option<u32>,

	unit: Option<u32>,

	report_size: Option<u32>,
	
	report_identifier: Option<NonZeroU32>,
	
	report_count: Option<u32>,
	
	reserved0: Option<u32>,
	
	reserved1: Option<u32>,
	
	reserved2: Option<u32>,
}

impl GlobalItems
{
	#[inline(alwaus)]
	fn parse_usage_page(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		if unlikely!(data > (u16::MAX as u32))
		{
			return Err(GlobalItemParseError::UsagePageTooBig { data })
		}
		self.usage_page = Some(data as u16);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_logical_minimum(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.logical_minimum_extent = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_logical_maximum(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.logical_maximum_extent = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_physical_minimum(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.physical_minimum_extent = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_physical_maximum(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.physical_maximum_extent = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_unit_exponent(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.unit_exponent = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_unit(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.unit = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_report_size(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.report_size = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_report_identifier(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		if unlikely!(data == 0)
		{
			return Err(GlobalItemParseError::ReportIdentifierZeroIsReserved)
		}
		
		self.report_identifier = Some(new_non_zero_u32(data));
		Ok(())
	}
	
	#[inline(always)]
	fn parse_report_count(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.report_count = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_reserved0(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.reserved0 = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_reserved1(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.reserved1 = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_reserved2(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		self.reserved2 = Some(data);
		Ok(())
	}
}
