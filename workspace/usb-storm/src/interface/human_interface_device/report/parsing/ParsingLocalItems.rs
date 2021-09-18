// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A set of local items.
#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct ParsingLocalItems
{
	usages: ParsingUsagesLocalItems,
	
	alternate_usages: Vec<ParsingUsagesLocalItems>,
	
	designators: Vec<InclusiveRange<DesignatorIndex>>,
	
	have_minimum_designator: Option<u32>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	have_minimum_string: Option<u32>,
	
	reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,
}

impl Deref for ParsingLocalItems
{
	type Target = ParsingUsagesLocalItems;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.usages
	}
}

impl DerefMut for ParsingLocalItems
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.usages
	}
}

impl ParsingLocalItems
{
	#[inline(always)]
	pub(super) fn finish_parsing(self, usage_page: ParsingUsagePage) -> Result<(Vec<Usage>, Vec<InclusiveRange<DesignatorIndex>>, Vec<Option<LocalizedStrings>>, Vec<ReservedLocalItem>, Vec<LongItem>, Vec<Vec<Usage>>), ReportParseError>
	{
		use LocalItemParseError::*;
		
		if unlikely!(self.have_minimum_designator.is_some())
		{
			Err(DesignatorParse(DesignatorParseError::DesignatorMinimumNotFollowedByDesignatorMaximum))?
		}
		
		if unlikely!(self.have_minimum_string.is_some())
		{
			Err(StringParse(StringParseError::StringMinimumNotFollowedByStringMaximum))?
		}
		
		let usages = self.usages.finish_parsing(usage_page)?;
		
		let alternate_usages = Self::finish_parsing_alternate_usages(self.alternate_usages, usage_page)?;
		
		Ok((usages, self.designators, self.strings, self.reserveds, self.longs, alternate_usages))
	}
	
	fn finish_parsing_alternate_usages(self_alternate_usages: Vec<ParsingUsagesLocalItems>, usage_page: ParsingUsagePage) -> Result<Vec<Vec<Usage>>, ReportParseError>
	{
		let mut alternate_usages = Vec::new_with_capacity(self_alternate_usages.len()).map_err(|cause| LocalItemParseError::AlternateUsageParse(AlternateUsageParseError::OutOfMemoryAllocatingAlternateUsages(cause)))?;
		for alternate_usage in self_alternate_usages
		{
			let usages = alternate_usage.finish_parsing(usage_page).map_err(ReportParseError::CouldNotFinishParsingAlternateUsage)?;
			alternate_usages.push_unchecked(usages)
		}
		Ok(alternate_usages)
	}
	
	#[inline(always)]
	fn push_alternate_usage(&mut self, alternate: ParsingUsagesLocalItems) -> Result<(), LocalItemParseError>
	{
		Ok(self.alternate_usages.try_push(alternate).map_err(AlternateUsageParseError::CouldNotPushAlternateUsage)?)
	}
	
	#[inline(always)]
	fn parse_designator(&mut self, data: u32) -> Result<(), LocalItemParseError>
	{
		Ok(self.designators.try_push(InclusiveRange(data ..= data)).map_err(DesignatorParseError::CouldNotPushDesignatorItem)?)
	}
	
	#[inline(always)]
	fn parse_designator_minimum(&mut self, minimum_data: u32) -> Result<(), LocalItemParseError>
	{
		if unlikely!(self.have_minimum_designator.is_some())
		{
			Err(DesignatorParseError::DesignatorMinimumCanNotBeFollowedByDesignatorMinimum)?
		}
		self.have_minimum_designator = Some(minimum_data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_designator_maximum(&mut self, maximum_data: u32) -> Result<(), LocalItemParseError>
	{
		use DesignatorParseError::*;
		
		match self.have_minimum_designator.take()
		{
			None => Err(DesignatorMaximumMustBePreceededByDesignatorMinimum)?,
			
			Some(minimum_data) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					Err(DesignatorMinimumMustBeLessThanMaximum)?
				}
				
				self.designators.try_push(InclusiveRange(minimum_data ..= maximum_data)).map_err(CouldNotPushDesignatorItem)?;
			}
		}
		Ok(())
	}
	
	#[inline(always)]
	fn parse_string(&mut self, data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<()>, LocalItemParseError>
	{
		let item = return_ok_if_dead!(Self::parse_string_descriptor_index(data, device_connection)?);
		match self.strings.try_push(item)
		{
			Ok(()) => Ok(Alive(())),
			
			Err(cause) => Err(StringParseError::CouldNotPushStringItem(cause))?
		}
	}
	
	#[inline(always)]
	fn parse_string_minimum(&mut self, minimum_data: u32) -> Result<(), LocalItemParseError>
	{
		if unlikely!(self.have_minimum_string.is_some())
		{
			Err(StringParseError::StringMinimumCanNotBeFollowedByStringMinimum)?
		}
		self.have_minimum_string = Some(minimum_data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_string_maximum(&mut self, maximum_data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<()>, LocalItemParseError>
	{
		use StringParseError::*;
		match self.have_minimum_string.take()
		{
			None => Err(StringMaximumMustBePreceededByStringMinimum)?,
			
			Some(minimum_data) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					Err(StringMinimumMustBeLessThanMaximum)?
				}
				
				for data in minimum_data ..= maximum_data
				{
					let dead_or_alive = self.parse_string(data, device_connection)?;
					return_ok_if_dead!(dead_or_alive)
				}
			}
		}
		Ok(Alive(()))
	}
	
	#[inline(always)]
	fn parse_reserved(&mut self, data: u32, data_width: DataWidth, tag: ReservedLocalItemTag) -> Result<(), LocalItemParseError>
	{
		let item = ReservedLocalItem::parse(data, data_width, tag);
		self.reserveds.try_push(item).map_err(LocalItemParseError::CouldNotPushReservedItem)
	}
	
	#[inline(always)]
	fn parse_long_item(&mut self, item_tag: u8, data: &[u8]) -> Result<(), LocalItemParseError>
	{
		let item = LongItem::parse(item_tag, data)?;
		Ok(self.longs.try_push(item).map_err(LongItemParseError::CouldNotPushLongItem)?)
	}
	
	#[inline(always)]
	fn parse_string_descriptor_index(data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<Option<LocalizedStrings>>, StringParseError>
	{
		use StringParseError::*;
		
		if data > (u8::MAX as u32)
		{
			return Err(StringDescriptorIndexOutOfRange { data })
		}
		let string_descriptor_index = data as u8;
		device_connection.find_string(string_descriptor_index).map_err(CouldNotFindString)
	}
}
