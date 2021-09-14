// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Report items, combined from globals and locals.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportItems
{
	usages: Vec<Usage>,
	
	report_identifier: Option<ReportIdentifier>,
	
	report_size: ReportSize,
	
	report_count: u32,
	
	report_bit_length: u32,
	
	logical_extent: InclusiveRange<i32>,
	
	physical_extent: InclusiveRange<i32>,

	physical_unit: (Option<Unit>, UnitExponent),
	
	designators: Vec<InclusiveRange<DesignatorIndex>>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	sets: Vec<Self>,
	
	global_reserved0: Option<ReservedGlobalItem>,
	
	global_reserved1: Option<ReservedGlobalItem>,
	
	global_reserved2: Option<ReservedGlobalItem>,
	
	local_reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,
}

impl ReportItems
{
	fn finish(globals: Cow<ParsingGlobalItemsSet>, parsing_locals: ParsingLocalItems) -> Result<Self, ReportParseError>
	{
		let (usage_ranges, designators, strings, local_reserveds, longs, sets) = parsing_locals.finish(globals.borrow())?;
		let (usage_page, logical_extent, physical_extent, physical_unit, report_size, report_count, report_bit_length, report_identifier, global_reserved0, global_reserved1, global_reserved2) = globals.into_owned();
		
		let usages =
		{
			let mut usages = Vec::new_with_capacity(usage_ranges.len()).map_err(OutOfMemoryAllocatingUsages)?;
			// TODO: Parse HUT!
			for usage_range in usage_ranges
			{
				let mut current = usage_range.inclusive_start();
				let end = usage_range.inclusive_end();
				loop
				{
					usages.try_push(current.finish(usage_page)).map_err(OutOfMemoryAllocatingUsages)?;
					
					if current == end
					{
						break
					}
					current = current.next();
				}
			}
			usages
		};
		
		use ReportParseError::*;
		Ok
		(
			Self
			{
				usages,
				
				report_identifier,
			
				report_size,
			
				report_count,
				
				report_bit_length,
				
				logical_extent,
			
				physical_extent,
			
				physical_unit,
			
				designators,
			
				strings,
				
				sets,
			
				global_reserved0,
			
				global_reserved1,
			
				global_reserved2,
			
				local_reserveds,
			
				longs,
			}
		)
	}
	
	/// Will not exceed `(i32::MAX as u32) + 1`.
	///
	/// Only relevant if the item is an array.
	#[inline(always)]
	pub fn number_of_array_items(&self) -> NonZeroU32
	{
		self.logical_extent.count()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn usages(&self) -> &[Usage]
	{
		&self.usages
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn report_identifier(&self) -> Option<ReportIdentifier>
	{
		self.report_identifier
	}
	
	/// This value is a number of bits.
	#[inline(always)]
	pub const fn report_size(&self) -> ReportSize
	{
		self.report_size
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn report_count(&self) -> u32
	{
		self.report_count
	}
	
	/// This value is a number of bits; it does not exceed 131_064 (a Linux limitation).
	#[inline(always)]
	pub const fn report_bit_length(&self) -> u32
	{
		self.report_bit_length
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn logical_extent(&self) -> &InclusiveRange<i32>
	{
		&self.logical_extent
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn physical_extent(&self) -> &InclusiveRange<i32>
	{
		&self.physical_extent
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn physical_unit(&self) -> (Option<Unit>, UnitExponent)
	{
		self.physical_unit
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn designators(&self) -> &[InclusiveRange<DesignatorIndex>]
	{
		&self.designators
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn strings(&self) -> &[Option<LocalizedStrings>]
	{
		&self.strings
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn sets(&self) -> &[Self]
	{
		&self.sets
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn global_reserved0(&self) -> Option<ReservedGlobalItem>
	{
		self.global_reserved0
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn global_reserved1(&self) -> Option<ReservedGlobalItem>
	{
		self.global_reserved1
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn global_reserved2(&self) -> Option<ReservedGlobalItem>
	{
		self.global_reserved2
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn local_reserveds(&self) -> &[ReservedLocalItem]
	{
		&self.local_reserveds
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn longs(&self) -> &[LongItem]
	{
		&self.longs
	}
}
