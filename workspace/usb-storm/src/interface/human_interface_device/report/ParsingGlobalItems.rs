// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A set of global items.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ParsingGlobalItems
{
	usage_page: Option<UsagePage>,
	
	report_size: Option<ReportSize>,
	
	report_identifier: Option<ReportIdentifier>,
	
	report_count: Option<u32>,
	
	logical_minimum_extent: Option<i32>,
	
	logical_maximum_extent: Option<i32>,
	
	physical_minimum_extent: Option<i32>,
	
	physical_maximum_extent: Option<i32>,
	
	unit_exponent: Option<UnitExponent>,

	unit: Option<Unit>,
	
	reserved0: Option<ReservedGlobalItem>,
	
	reserved1: Option<ReservedGlobalItem>,
	
	reserved2: Option<ReservedGlobalItem>,
}

impl ParsingGlobalItems
{
	#[inline(always)]
	fn finish(&self) -> Result<ParsingGlobalItemsSet, GlobalItemParseError>
	{
		use GlobalItemParseError::*;
		
		let logical_extent = match (self.logical_minimum_extent, self.logical_maximum_extent)
		{
			(Some(minimum), Some(maximum)) => if unlikely!(minimum > maximum)
			{
				return Err(MinimumLogicalExtentExceedsMaximum { minimum, maximum })
			}
			else
			{
				InclusiveRange(minimum ..= maximum)
			},
			
			(Some(minimum), None) => return Err(MissingMaximumLogicalExtent { minimum }),
			
			(None, Some(maximum)) => return Err(MissingMinimumLogicalExtent { maximum }),
			
			_ => return Err(MissingMinimumAndMaximumLogicalExtent)
		};
		
		let physical_extent =
		{
			let physical_extent = match (self.physical_minimum_extent, self.physical_maximum_extent)
			{
				(Some(0), Some(0)) => logical_extent.clone(),
				
				(Some(minimum), Some(maximum)) => if unlikely!(minimum > maximum)
				{
					return Err(MinimumPhysicalExtentExceedsMaximum { minimum, maximum })
				}
				else
				{
					InclusiveRange(minimum ..= maximum)
				},
				
				_ => logical_extent.clone(),
			};
			
			if unlikely!(physical_extent.inclusive_start() == physical_extent.inclusive_end())
			{
				return Err(PhysicalExtentWouldCauseDivisionByZeroForResolution)
			}
			physical_extent
		};
		
		let unit_exponent = self.unit_exponent.unwrap_or_default();
		
		let report_size = self.report_size.ok_or(NoReportSize)?;
		
		let report_count = self.report_count.ok_or(NoReportCount)?;
		
		let usage_page = self.usage_page.ok_or(NoUsagePage)?;
		
		let report_bit_length =
		{
			let report_bit_length = (report_size as u64) * (report_count as u64);
			// This check is taken from Linux.
			const HID_MAX_BUFFER_SIZE: u64 = 16384;
			const Maximum: u64 = (HID_MAX_BUFFER_SIZE - 1) << 3;
			if report_bit_length > Maximum
			{
				return Err(ReportBitLengthIsTooLarge { report_bit_length })
			}
			report_bit_length as u32
		};
		
		Ok((usage_page, logical_extent, physical_extent, (self.unit, unit_exponent), report_size, report_count, report_bit_length, self.report_identifier, self.reserved0, self.reserved1, self.reserved2))
	}
	
	#[inline(always)]
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
	fn parse_logical_minimum(&mut self, data: u32, data_width: DataWidth)
	{
		self.logical_minimum_extent = Some(Self::convert_data_to_signed_value(data, data_width));
	}
	
	#[inline(always)]
	fn parse_logical_maximum(&mut self, data: u32, data_width: DataWidth)
	{
		self.logical_maximum_extent = Some(Self::convert_data_to_signed_value(data, data_width));
	}
	
	#[inline(always)]
	fn parse_physical_minimum(&mut self, data: u32, data_width: DataWidth)
	{
		self.physical_minimum_extent = Some(Self::convert_data_to_signed_value(data, data_width));
	}
	
	#[inline(always)]
	fn parse_physical_maximum(&mut self, data: u32, data_width: DataWidth)
	{
		self.physical_maximum_extent = Some(Self::convert_data_to_signed_value(data, data_width));
	}
	
	#[inline(always)]
	fn parse_unit_exponent(&mut self, data: u32, data_width: DataWidth)
	{
		self.unit_exponent = Some(UnitExponent::parse(data, data_width));
	}
	
	#[inline(always)]
	fn parse_unit(&mut self, data: u32)
	{
		self.unit = Some(Unit::parse(data));
	}
	
	#[inline(always)]
	fn parse_report_size(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		if unlikely!(data > 256)
		{
			return Err(GlobalItemParseError::ReportSizeGreaterThan256Bytes { data })
		}
		self.report_size = Some(data as u16);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_report_identifier(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		use GlobalItemParseError::*;
		
		if unlikely!(data == 0)
		{
			return Err(ReportIdentifierZeroIsReserved)
		}
		
		// This value is from Linux.
		const HID_MAX_IDS: u32 = 256;
		
		if unlikely!(data >= HID_MAX_IDS)
		{
			return Err(ReportIdentifierTooLarge { data })
		}
		
		self.report_identifier = Some(new_non_zero_u16(data as u16));
		Ok(())
	}
	
	#[inline(always)]
	fn parse_report_count(&mut self, data: u32) -> Result<(), GlobalItemParseError>
	{
		// This value is from Linux.
		const HID_MAX_USAGES: u32 = 12288;
		
		if unlikely!(data > HID_MAX_USAGES)
		{
			return Err(GlobalItemParseError::ReportCountTooLarge { data })
		}
		self.report_count = Some(data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_reserved0(&mut self, data: u32, data_width: DataWidth)
	{
		self.reserved0 = Some(ReservedGlobalItem::parse(data, data_width));
	}
	
	#[inline(always)]
	fn parse_reserved1(&mut self, data: u32, data_width: DataWidth)
	{
		self.reserved1 = Some(ReservedGlobalItem::parse(data, data_width));
	}
	
	#[inline(always)]
	fn parse_reserved2(&mut self, data: u32, data_width: DataWidth)
	{
		self.reserved2 = Some(ReservedGlobalItem::parse(data, data_width));
	}
	
	#[inline(always)]
	fn convert_data_to_signed_value(data: u32, data_width: DataWidth) -> i32
	{
		#[inline(always)]
		const fn is_signed<const bit_index: u8>(data: u32) -> bool
		{
			let signed_bit = 1 << (bit_index as u32);
			(data & signed_bit) != 0
		}
		
		use DataWidth::*;
		match data_width
		{
			Widthless =>
			{
				debug_assert_eq!(data, 0);
				0
			}
			
			EightBit =>
			{
				debug_assert!(data <= (u8::MAX as u32));
				if is_signed::<7>(data)
				{
					data as u8 as i8 as i32
				}
				else
				{
					data as u8 as i32
				}
			},
			
			SixteenBit =>
			{
				debug_assert!(data <= (u16::MAX as u32));
				if is_signed::<15>(data)
				{
					data as u16 as i16 as i32
				}
				else
				{
					data as u16 as i32
				}
			},
			
			ThirtyTwoBit => data as i32,
		}
	}
}
