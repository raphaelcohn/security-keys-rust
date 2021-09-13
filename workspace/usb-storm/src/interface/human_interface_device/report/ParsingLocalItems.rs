// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A set of global items.
#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParsingLocalItems
{
	usages: Vec<RangeInclusive<Usage>>,
	
	have_minimum_usage: Option<(u32, DataWidth)>,
	
	designators: Vec<RangeInclusive<DesignatorIndex>>,
	
	have_minimum_designator: Option<u32>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	have_minimum_string: Option<u32>,
	
	reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,

	sets: Vec<LocalItems>,
}

impl TryClone for ParsingLocalItems
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

impl ParsingLocalItems
{
	#[inline(always)]
	fn finish(self) -> Result<LocalItems, LocalItemParseError>
	{
		use LocalItemParseError::*;
		
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
	fn push_set(&mut self, local_set: Self) -> Result<(), LocalItemParseError>
	{
		self.sets.try_push(local_set.finish()?).map_err(LocalItemParseError::CouldNotPushSet)
	}
	
	#[inline(always)]
	fn parse_usage(&mut self, data: u32, data_width: DataWidth) -> Result<(), LocalItemParseError>
	{
		let usage = Usage::parse(data, data_width);
		self.usages.try_push(usage ..= usage).map_err(LocalItemParseError::CouldNotPushUsageItem)
	}
	
	#[inline(always)]
	fn parse_usage_minimum(&mut self, minimum_data: u32, minimum_data_width: DataWidth) -> Result<(), LocalItemParseError>
	{
		if unlikely!(self.have_minimum_usage.is_some())
		{
			return Err(LocalItemParseError::UsageMinimumCanNotBeFollowedByUsageMinimum)
		}
		self.have_minimum_usage = Some((minimum_data, minimum_data_width));
		Ok(())
	}
	
	#[inline(always)]
	fn parse_usage_maximum(&mut self, maximum_data: u32, maximum_data_width: DataWidth) -> Result<(), LocalItemParseError>
	{
		use LocalItemParseError::*;
		match self.have_minimum_usage.take()
		{
			None => return Err(UsageMaximumMustBePreceededByUsageMinimum),
			
			Some((minimum_data, minimum_data_width)) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					return Err(UsageMinimumMustBeLessThanMaximum)
				}
				
				use DataWidth::*;
				match (minimum_data_width, maximum_data_width)
				{
					(ThirtyTwoBit, ThirtyTwoBit) => (),
					
					(ThirtyTwoBit, _) => return Err(UsageMinimumAndMaximumMustBeSimilar { minimum_data_width, maximum_data_width }),
					
					(_, ThirtyTwoBit) => return Err(UsageMinimumAndMaximumMustBeSimilar { minimum_data_width, maximum_data_width }),
					
					_ => (),
				}
				
				let minimum = Usage::parse(minimum_data, minimum_data_width);
				let maximum = Usage::parse(maximum_data, maximum_data_width);
				self.usages.try_push(minimum ..= maximum).map_err(CouldNotPushUsageItem)?;
			}
		}
		Ok(())
	}
	
	#[inline(always)]
	fn parse_designator(&mut self, data: u32) -> Result<(), LocalItemParseError>
	{
		self.designators.try_push(data ..= data).map_err(LocalItemParseError::CouldNotPushDesignatorItem)
	}
	
	#[inline(always)]
	fn parse_designator_minimum(&mut self, minimum_data: u32) -> Result<(), LocalItemParseError>
	{
		if unlikely!(self.have_minimum_designator.is_some())
		{
			return Err(LocalItemParseError::DesignatorMinimumCanNotBeFollowedByDesignatorMinimum)
		}
		self.have_minimum_designator = Some(minimum_data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_designator_maximum(&mut self, maximum_data: u32) -> Result<(), LocalItemParseError>
	{
		use LocalItemParseError::*;
		match self.have_minimum_designator.take()
		{
			None => return Err(DesignatorMaximumMustBePreceededByDesignatorMinimum),
			
			Some(minimum_data) =>
			{
				if unlikely!(minimum_data > maximum_data)
				{
					return Err(DesignatorMinimumMustBeLessThanMaximum)
				}
				
				self.designators.try_push(minimum_data ..= maximum_data).map_err(CouldNotPushDesignatorItem)?;
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
			
			Err(cause) => Err(LocalItemParseError::CouldNotPushStringItem(cause))
		}
	}
	
	#[inline(always)]
	fn parse_string_minimum(&mut self, minimum_data: u32) -> Result<(), LocalItemParseError>
	{
		if unlikely!(self.have_minimum_string.is_some())
		{
			return Err(LocalItemParseError::StringMinimumCanNotBeFollowedByStringMinimum)
		}
		self.have_minimum_string = Some(minimum_data);
		Ok(())
	}
	
	#[inline(always)]
	fn parse_string_maximum(&mut self, maximum_data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<()>, LocalItemParseError>
	{
		use LocalItemParseError::*;
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
	fn parse_reserved(&mut self, data: u32, data_width: DataWidth, tag: ReservedLocalItemTag) -> Result<(), LocalItemParseError>
	{
		let item = ReservedLocalItem::parse(data, data_width, tag);
		self.reserveds.try_push(item).map_err(LocalItemParseError::CouldNotPushReservedItem)
	}
	
	#[inline(always)]
	fn parse_long_item(&mut self, item_tag: u8, data: &[u8]) -> Result<(), LocalItemParseError>
	{
		let item = LongItem::parse(item_tag, data)?;
		self.longs.try_push(item).map_err(LocalItemParseError::CouldNotPushLongItem)
	}
	
	#[inline(always)]
	fn parse_string_descriptor_index(data: u32, device_connection: &DeviceConnection) -> Result<DeadOrAlive<Option<LocalizedStrings>>, LocalItemParseError>
	{
		if data > (u8::MAX as u32)
		{
			return Err(LocalItemParseError::StringDescriptorIndexOutOfRange { data })
		}
		let string_descriptor_index = data as u8;
		device_connection.find_string(string_descriptor_index).map_err(LocalItemParseError::CouldNotFindString)
	}
}
