// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug)]
struct ReportParser<'a>
{
	device_connection: &'a DeviceConnection<'a>,

	item_state_table_stack: Stack<ItemStateTable>,

	collection_stack: Stack<CollectionMainItem>,
}

impl<'a> ReportParser<'a>
{
	#[inline(always)]
	fn new(device_connection: &'a DeviceConnection) -> Result<Self, ReportParseError>
	{
		let current_globals = Self::new_globals()?;
		Ok
		(
			Self
			{
				device_connection,
				
				item_state_table_stack: Stack::new()?,
				
				collection_stack: Stack::new()?,
			}
		)
	}
	
	#[inline(always)]
	fn get_and_parse(self, reusable_buffer: &mut ReusableBuffer, interface_number: InterfaceNumber, report_total_length: u16) -> Result<DeadOrAlive<CollectionCommon>, ReportParseError>
	{
		let dead_or_alive = self.get_report_descriptor_bytes(reusable_buffer, interface_number, report_total_length)?;
		let mut descriptor_bytes: &[u8] = return_ok_if_dead!(dead_or_alive);
		self.parse_items(descriptor_bytes)
	}
	
	#[inline(always)]
	fn parse_items(&mut self, mut descriptor_bytes: &[u8]) -> Result<DeadOrAlive<CollectionCommon>, ReportParseError>
	{
		use ReportParseError::*;
		
		let mut index = 0;
		while !descriptor_bytes.is_empty()
		{
			let length = descriptor_bytes.len();
			
			let item_prefix = descriptor_bytes.u8(0);
			let is_long_item = item_prefix == 0b1111_11_10;
			let exclusive_end_of_data_index = if is_long_item
			{
				if unlikely!(length < 2)
				{
					return Err(LongItemTooShort)
				}
				let bDataSize = descriptor_bytes.u8(1);
				let bLongItemTag = descriptor_bytes.u8(2);
				
				let (exclusive_end_of_data_index, data) = Self::get_item_data(descriptor_bytes, 3, bDataSize)?;
				self.parse_long_item(bTag, data)?;
				exclusive_end_of_data_index
			}
			else
			{
				let bSize = item_prefix & 0b11;
				let bType = (item_prefix >> 2) & 0b11;
				let bTag = item_prefix >> 4;
				
				let (exclusive_end_of_data_index, data, was_32_bits_wide) = Self::get_short_item_data(descriptor_bytes, bSize)?;
				let alive_or_dead = self.parse_short_item(unsafe { transmute(bType) }, bTag, data, was_32_bits_wide)?;
				return_ok_if_dead!(alive_or_dead);
				exclusive_end_of_data_index
			};
			
			descriptor_bytes = descriptor_bytes.get_unchecked_range_safe(exclusive_end_of_data_index .. );
		}
		
		let common = self.collection_stack.consume()?.common;
		Ok(Alive(common))
	}
	
	#[inline(always)]
	fn parse_long_item(&mut self, item_tag: u8, data: &[u8]) -> Result<(), ReportParseError>
	{;
		Ok(self.locals().parse_long_item(item_tag, data)?)
	}
	
	#[inline(always)]
	fn parse_short_item(&mut self, short_item_type: ShortItemType, item_tag: u8, data: u32, was_32_bits_wide: bool) -> Result<DeadOrAlive<()>, ReportParseError>
	{
		use ReportParseError::*;
		use ShortItemType::*;
		
		match short_item_type
		{
			Main =>
			{
				let (globals, locals, ) = self.finish_globals_and_locals()?;
				
				use ReservedMainItemTag::*;
				let report = match item_tag
				{
					0b0000 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _0),
					0b0001 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _1),
					0b0010 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _2),
					0b0011 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _3),
					
					0b0100 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _4),
					0b0101 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _5),
					0b0110 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _6),
					0b0111 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _7),
					
					0b1000 => Report::parse_input(data, globals, locals),
					0b1001 => Report::parse_output(data, globals, locals),
					0b1011 => Report::parse_feature(data, globals, locals),
					0b1010 =>
					{
						use CollectionDescription::*;
						self.collection_stack.push_value
						(
							CollectionMainItem::new
							(
								globals,
								
								locals,
								
								match data
								{
									0x00 => Physical,
									
									0x01 => Application,
									
									0x02 => Logical,
									
									0x03 => Report,
									
									0x04 => NamedArray,
									
									0x05 => UsageSwitch,
									
									0x06 => UsageModifier,
									
									0x07 ..= 0x7F => Reserved(data),
									
									0x80 ..= 0xFF => VendorSpecific(data as u8),
									
									0x100 ..= 0xFFFF_FFFF => Reserved(data),
								}
							)
						);
						
						return Ok(Alive(()))
					}
					
					0b1100 =>
					{
						let mut collection = self.collection_stack.pop().ok_or(TooManyCollectionPops)?;
						collection.end_data = data;
						Report::Collection(collection)
					}
					0b1101 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _8),
					0b1110 => Report::parse_reserved(data, was_32_bits_wide, globals, locals, _9),
					0b1111 => unreachable!("Long tag"),
					
					_ => unreachable!(),
				};
				
				self.current_collection().push_report(report)?
			},
			
			Global =>
			{
				match item_tag
				{
					0b0000 => self.globals()?.parse_usage_page(data)?,
					0b0001 => self.globals()?.parse_logical_minimum(data)?,
					0b0010 => self.globals()?.parse_logical_maximum(data)?,
					0b0011 => self.globals()?.parse_physical_minimum(data)?,
					
					0b0100 => self.globals()?.parse_physical_maximum(data)?,
					0b0101 => self.globals()?.parse_unit_exponent(data)?,
					0b0110 => self.globals()?.parse_unit(data)?,
					0b0111 => self.globals()?.parse_report_size(data)?,
					
					0b1000 => self.globals()?.parse_report_identifier(data)?,
					0b1001 => self.globals()?.parse_report_count(data)?,
					0b1010 => self.push_item_state_table(),
					0b1011 => self.pop_item_state_table(),
					
					0b1100 => self.globals()?.parse_reserved0(data)?,
					0b1101 => self.globals()?.parse_reserved1(data)?,
					0b1110 => self.globals()?.parse_reserved2(data)?,
					0b1111 => unreachable!("Long tag"),
					
					_ => unreachable!(),
				}
			},
			
			Local =>
			{
				use ReservedLocalItemTag::*;
				
				match item_tag
				{
					0b0000 => self.locals().parse_usage(data, was_32_bits_wide)?,
					0b0001 => self.locals().parse_usage_minimum(data, was_32_bits_wide)?,
					0b0010 => self.locals().parse_usage_maximum(data, was_32_bits_wide)?,
					0b0011 => self.locals().parse_designator(data)?,
					
					0b0100 => self.locals().parse_designator_minimum(data)?,
					0b0101 => self.locals().parse_designator_maximum(data)?,
					0b0110 => self.locals().parse_reserved(data, was_32_bits_wide, _0)?,
					0b0111 => return Ok(self.locals().parse_string(data, self.device_connection)?),
					
					0b1000 => self.locals().parse_string_minimum(data)?,
					0b1001 => return Ok(self.locals().parse_string_maximum(data, self.device_connection)?),
					0b1010 => match data
					{
						0 => match self.locals_stack().pop()
						{
							None => Err(ClosedTooManyOpenLocalSets),
							
							Some(local_set) =>
							{
								self.locals().push_set(local_set)?
							}
						}
						
						1 => self.locals_stack().push(),
						
						_ => return Err(InvalidLocalDelimiter { data }),
					},
					0b1011 => self.locals().parse_reserved(data, was_32_bits_wide, _1)?,
					
					0b1100 => self.locals().parse_reserved(data, was_32_bits_wide, _1)?,
					0b1101 => self.locals().parse_reserved(data, was_32_bits_wide, _3)?,
					0b1110 => self.locals().parse_reserved(data, was_32_bits_wide, _4)?,
					0b1111 => unreachable!("Long tag"),
					
					_ => unreachable!(),
				}
			},
		}
		
		Ok(Alive(()))
	}
	
	#[inline(always)]
	fn get_short_item_data(descriptor_bytes: &[u8], bSize: u8) -> Result<(usize, u32, bool), ReportParseError>
	{
		const inclusive_start_of_data_index: u8 = 1;
		let outcome = match bSize
		{
			0 =>
			{
				let exclusive_end_of_data_index = Self::get_exclusive_end_of_data_index(descriptor_bytes, inclusive_start_of_data_index, 0)?;
				(exclusive_end_of_data_index, 0, false)
			},
			
			1 =>
			{
				let (exclusive_end_of_data_index, short_item_data) = Self::get_item_data(descriptor_bytes, inclusive_start_of_data_index, 1)?;
				(exclusive_end_of_data_index, short_item_data.u8(0) as u32, false)
			},
			
			2 =>
			{
				let (exclusive_end_of_data_index, short_item_data) = Self::get_item_data(descriptor_bytes, inclusive_start_of_data_index, 2)?;
				(exclusive_end_of_data_index, short_item_data.u16(0) as u32, false)
			},
			
			3 =>
			{
				// Yes, this is correct.
				const Four: u8 = 4;
				let (exclusive_end_of_data_index, short_item_data) = Self::get_item_data(descriptor_bytes, inclusive_start_of_data_index, Four)?;
				(exclusive_end_of_data_index, short_item_data.u32(0), true)
			},
			
			_ => unreachable!("Exceeds the size of a short piece of data")
		};
		
		Ok(outcome)
	}
	
	#[inline(always)]
	fn get_item_data(descriptor_bytes: &[u8], inclusive_start_of_data_index: u8, size: u8) -> Result<(usize, &[u8]), ReportParseError>
	{
		let exclusive_end_of_data_index = Self::get_exclusive_end_of_data_index(descriptor_bytes, inclusive_start_of_data_index, size)?;
		Ok((exclusive_end_of_data_index, descriptor_bytes.get_unchecked_range_safe((inclusive_start_of_data_index as usize) .. exclusive_end_of_data_index)))
	}
	
	#[inline(always)]
	fn get_exclusive_end_of_data_index(descriptor_bytes: &[u8], inclusive_start_of_data_index: u8, size: u8) -> Result<usize, ReportParseError>
	{
		let exclusive_end_of_data_index = (inclusive_start_of_data_index + size) as usize;
		if unlikely!(exclusive_end_of_data_index > length)
		{
			Err(ReportParseError::ItemHasDataSizeExceedingRemainingBytes { size })
		}
		Ok(exclusive_end_of_data_index)
	}
	
	#[inline(always)]
	fn get_report_descriptor_bytes(&self, reusable_buffer: &mut ReusableBuffer, interface_number: InterfaceNumber, report_total_length: u16) -> Result<DeadOrAlive<&[u8]>, ReportParseError>
	{
		use ReportParseError::*;
		
		let dead_or_alive = get_human_interface_device_report_interface_descriptor(self.device_connection.device_handle_non_null(), interface_number, reusable_buffer.as_maybe_uninit_slice()).map_err(GetDescriptor)?;
		match return_ok_if_dead!(dead_or_alive)
		{
			None => Err(UnsupportedEvenThisIsAHumanInterfaceDevice),
			
			Some(descriptor_bytes) => Ok(Alive(descriptor_bytes)),
		}
	}
	
	#[inline(always)]
	fn current_collection(&mut self) -> &mut CollectionMainItem
	{
		self.collection_stack.current()
	}
	
	#[inline(always)]
	fn finish_globals_and_locals(&mut self) -> Result<(Rc<GlobalItems>, LocalItems), ReportParseError>
	{
		Ok
		(
			(
				self.globals_inner().clone(),
				take(self.locals()).consume()?.finish()?
			)
		)
	}
	
	#[inline(always)]
	fn globals(&mut self) -> Result<&mut GlobalItems, ReportParseError>
	{
		match Rc::get_mut(self.globals_inner())
		{
			None =>
			{
				self.current_item_state_table().globals = Self::new_globals()?;
				Ok(unsafe { Rc::get_mut_unchecked(self.globals_inner()) })
			}
			
			Some(globals) => Ok(globals),
		}
	}
	
	#[inline(always)]
	fn new_globals() -> Result<Rc<GlobalItems>, ReportParseError>
	{
		Rc::try_new(Default::default()).map_err(ReportParseError::CouldNotAllocateCurrentGlobals)
	}
	
	#[inline(always)]
	fn locals(&mut self) -> &mut ParsedLocalItems
	{
		self.locals_stack().current()
	}
	
	#[inline(always)]
	fn globals_inner(&mut self) -> &mut Rc<GlobalItems>
	{
		&mut self.current_item_state_table().globals
	}
	
	#[inline(always)]
	fn locals_stack(&mut self) -> &mut Stack<ParsedLocalItems>
	{
		&mut self.current_item_state_table().locals
	}
	
	#[inline(always)]
	fn push_item_state_table(&mut self) -> Result<(), ReportParseError>
	{
		let cloned_item_state_table = self.current_item_state_table().try_clone().map_err(|cause| ReportParseError::GlobalItemParse(GlobalItemParseError::CouldNotPushStack(cause)))?;
		self.item_state_table_stack.push_value(cloned_item_state_table);
		Ok(())
	}
	
	#[inline(always)]
	fn pop_item_state_table(&mut self) -> Result<(), ReportParseError>
	{
		if self.item_state_table_stack.pop().is_some()
		{
			Ok(())
		}
		else
		{
			Err(ReportParseError::GlobalItemParse(GlobalItemParseError::TooManyStackPops))
		}
	}
	
	#[inline(always)]
	fn current_item_state_table(&mut self) -> &mut ItemStateTable
	{
		self.item_state_table_stack.current()
	}
}
