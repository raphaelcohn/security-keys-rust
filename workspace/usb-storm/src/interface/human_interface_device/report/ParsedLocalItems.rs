// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A set of global items.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParsedLocalItems
{
	usages: Vec<Usage>,
	
	have_minimum_usage: Option<(u32, bool)>,
	
	designators: Vec<DesignatorIndex>,
	
	have_minimum_designator: Option<u32>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	have_minimum_string: Option<u32>,
	
	reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,

	sets: Vec<LocalItems>,
}

impl TryClone for ParsedLocalItems
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok
		(
			Self
			{
				usages: self.usages.try_clone()?,
				
				have_minimum_usage: self.have_minimum_usage,
				
				designators: self.designators.try_clone()?,
				
				have_minimum_designator: self.have_minimum_designator,
				
				strings: self.strings.try_clone()?,
				
				have_minimum_string: self.have_minimum_string,
				
				reserveds: self.reserveds.try_clone()?,
				
				longs: self.longs.try_clone()?,
				
				sets: self.sets.try_clone()?,
			}
		)
	}
}

impl ParsedLocalItems
{
	#[inline(always)]
	fn finish(self) -> Result<LocalItems, ParsedLocalItemParseError>
	{
		use ParsedLocalItemParseError::*;
		
		if unlikely!(self.have_minimum_usage.is_some())
		{
			return Err(UsageMinimumNotFollowedByUsageMaximum)
		}
		if unlikely!(self.have_minimum_designator.is_some())
		{
			return Err(DesignatorMinimumNotFollowedByDesignatorMaximum)
		}
		if unlikely!(self.have_minimum_string.is_some())
		{
			return Err(StringMinimumNotFollowedByStringMaximum)
		}
		
		Ok
		(
			LocalItems
			{
				usages: self.usages,
				
				designators: self.designators,
				
				strings: self.strings,
				
				reserveds: self.reserveds,
				
				longs: self.longs,
			
				sets: self.sets,
			}
		)
	}
	
	#[inline(always)]
	fn push_set(&mut self, local_set: Self) -> Result<(), ParsedLocalItemParseError>
	{
		self.sets.try_push(local_set.finish()?).map_err(ParsedLocalItemParseError::CouldNotPushSet)
	}
	
	#[inline(always)]
	fn parse_usage(&mut self, data: u32, was_32_bits_wide: bool) -> Result<(), ParsedLocalItemParseError>
	{
		self.usages.try_push(Usage::parse(data, was_32_bits_wide)).map_err(ParsedLocalItemParseError::CouldNotPushUsageItem)
	}
	
	#[inline(always)]
	fn parse_usage_minimum(&mut self, minimum_data: u32, minimum_was_32_bits_wide: bool) -> Result<(), ParsedLocalItemParseError>
	{
		if unlikely!(self.have_minimum_usage.is_some())
		{
			return Err(ParsedLocalItemParseError::UsageMinimumCanNotBeFollowedByUsageMinimum)
		}
		self.have_minimum_usage = Some((minimum_data, minimum_was_32_bits_wide));
		Ok(())
	}
	
	#[inline(always)]
	fn parse_usage_maximum(&mut self, maximum_data: u32, maximum_was_32_bits_wide: bool) -> Result<(), ParsedLocalItemParseError>
	{
		use ParsedLocalItemParseError::*;
		match self.have_minimum_usage.take()
		{
			None => return Err(UsageMaximumMustBePreceededByUsageMinimum),
			
			Some((minimum_data, minimum_was_32_bits_wide)) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					return Err(UsageMinimumMustBeLessThanMaximum)
				}
				
				if unlikely!(minimum_was_32_bits_wide != maximum_was_32_bits_wide)
				{
					return Err(UsageMinimumAndMaximumMustBeTheSameWidth)
				}
				
				for data in minimum_data ..= maximum_data
				{
					self.parse_usage(data, minimum_was_32_bits_wide)?
				}
			}
		}
		Ok(())
	}
	
	#[inline(always)]
	fn parse_designator(&mut self, data: u32) -> Result<(), ParsedLocalItemParseError>
	{
		self.designators.try_push(data).map_err(ParsedLocalItemParseError::CouldNotPushDesignatorItem)
	}
	
	#[inline(always)]
	fn parse_designator_minimum(&mut self, minimum_data: u32) -> Result<(), ParsedLocalItemParseError>
	{
		if unlikely!(self.have_minimum_designator.is_some())
		{
			return Err(ParsedLocalItemParseError::DesignatorMinimumCanNotBeFollowedByDesignatorMinimum)
		}
		self.have_minimum_designator = Some(minimum_data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_designator_maximum(&mut self, maximum_data: u32) -> Result<(), ParsedLocalItemParseError>
	{
		use ParsedLocalItemParseError::*;
		match self.have_minimum_designator.take()
		{
			None => return Err(DesignatorMaximumMustBePreceededByDesignatorMinimum),
			
			Some(minimum_data) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					return Err(DesignatorMinimumMustBeLessThanMaximum)
				}
				
				for data in minimum_data ..= maximum_data
				{
					self.parse_designator(data)?
				}
			}
		}
		Ok(())
	}
	
	#[inline(always)]
	fn parse_string(&mut self, data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<()>, ParsedLocalItemParseError>
	{
		let item = return_ok_if_dead!(Self::parse_string_descriptor_index(data, device_connection)?);
		match self.strings.try_push(item)
		{
			Ok(()) => Ok(Alive(())),
			
			Err(cause) => Err(ParsedLocalItemParseError::CouldNotPushStringItem(cause))
		}
	}
	
	#[inline(always)]
	fn parse_string_minimum(&mut self, minimum_data: u32) -> Result<(), ParsedLocalItemParseError>
	{
		if unlikely!(self.have_minimum_string.is_some())
		{
			return Err(ParsedLocalItemParseError::StringMinimumCanNotBeFollowedByStringMinimum)
		}
		self.have_minimum_string = Some(minimum_data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_string_maximum(&mut self, maximum_data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<()>, ParsedLocalItemParseError>
	{
		use ParsedLocalItemParseError::*;
		match self.have_minimum_string.take()
		{
			None => return Err(StringMaximumMustBePreceededByStringMinimum),
			
			Some(minimum_data) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					return Err(StringMinimumMustBeLessThanMaximum)
				}
				
				for data in minimum_data ..= maximum_data
				{
					return_ok_if_dead!(self.parse_string(data, device_connection)?)
				}
			}
		}
		Ok(Alive(()))
	}
	
	#[inline(always)]
	fn parse_reserved(&mut self, data: u32, was_32_bits_wide: bool, tag: ReservedLocalItemTag) -> Result<(), ParsedLocalItemParseError>
	{
		let item = ReservedLocalItem
		{
			tag,
			
			data,
			
			was_32_bits_wide
		};
		self.reserveds.try_push(item).map_err(ParsedLocalItemParseError::CouldNotPushReservedItem)
	}
	
	#[inline(always)]
	fn parse_long_item(&mut self, item_tag: u8, data: &[u8]) -> Result<(), ParsedLocalItemParseError>
	{
		let item = LongItem::parse(item_tag, data)?;
		self.longs.try_push(item).map_err(ParsedLocalItemParseError::CouldNotPushLongItem)
	}
	
	#[inline(always)]
	fn parse_string_descriptor_index(data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<Option<LocalizedStrings>>, ParsedLocalItemParseError>
	{
		if data > (u8::MAX as u32)
		{
			return Err(ParsedLocalItemParseError::StringDescriptorIndexOutOfRange { data })
		}
		let string_descriptor_index = data as u8;
		device_connection.find_string(string_descriptor_index).map_err(ParsedLocalItemParseError::CouldNotFindString)
	}
}
