// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct ReportParser<'a>
{
	device_connection: &'a DeviceConnection<'a>,

	globals_stack: Stack<Rc<ParsingGlobalItems>>,

	collection_stack: Stack<CollectionMainItem>,
	
	locals: ParsingLocalItems,
	
	locals_alternate_usages: Option<ParsingUsagesLocalItems>,
}

impl<'a> ReportParser<'a>
{
	#[inline(always)]
	pub(crate) fn new(device_connection: &'a DeviceConnection) -> Result<Self, ReportParseError>
	{
		Ok
		(
			Self
			{
				device_connection,
				
				globals_stack:
				{
					let items = ParsingGlobalItems::default();
					let globals = Rc::try_new(items).map_err(|cause| ReportParseError::GlobalItemParse(GlobalItemParseError::CouldNotAllocateGlobals(cause)))?;
					Stack::new(globals)?
				},
				
				collection_stack: Stack::new(CollectionMainItem::new_for_collections_stack())?,
				
				locals: ParsingLocalItems::default(),
				
				locals_alternate_usages: None,
			}
		)
	}
	
	#[inline(always)]
	pub(crate) fn get_and_parse(mut self, reusable_buffer: &mut ReusableBuffer, interface_number: InterfaceNumber, report_total_length: u16) -> Result<DeadOrAlive<CollectionCommon>, ReportParseError>
	{
		let dead_or_alive = self.get_report_descriptor_bytes(reusable_buffer, interface_number, report_total_length)?;
		let descriptor_bytes: &[u8] = return_ok_if_dead!(dead_or_alive);
		self.parse_items(descriptor_bytes)
	}
	
	#[inline(always)]
	fn parse_items(&mut self, mut descriptor_bytes: &[u8]) -> Result<DeadOrAlive<CollectionCommon>, ReportParseError>
	{
		use ReportParseError::*;
		
		while !descriptor_bytes.is_empty()
		{
			let length = descriptor_bytes.len();
			
			let item_prefix = descriptor_bytes.u8(0);
			let is_long_item = item_prefix == 0b1111_11_10;
			let exclusive_end_of_data_index = if is_long_item
			{
				if unlikely!(length < 2)
				{
					return Err(LocalItemParse(LocalItemParseError::LongItemParse(LongItemParseError::LongItemTooShort)))
				}
				let bDataSize = descriptor_bytes.u8(1);
				let bLongItemTag = descriptor_bytes.u8(2);
				
				let (exclusive_end_of_data_index, data) = Self::get_item_data(descriptor_bytes, 3, bDataSize)?;
				self.parse_long_item(bLongItemTag, data)?;
				exclusive_end_of_data_index
			}
			else
			{
				let bSize = item_prefix & 0b11;
				let bType = (item_prefix >> 2) & 0b11;
				let bTag = item_prefix >> 4;
				
				let (exclusive_end_of_data_index, data, data_width) = Self::get_short_item_data(descriptor_bytes, bSize)?;
				let alive_or_dead = self.parse_short_item(unsafe { transmute(bType) }, bTag, data, data_width)?;
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
	{
		if unlikely!(self.locals_alternate_usages.is_some())
		{
			Err(LocalItemParseError::Delimited(DelimitedLocalItemParseError::Long))?
		}
		
		Ok(self.locals.parse_long_item(item_tag, data)?)
	}
	
	#[inline(always)]
	fn parse_short_item(&mut self, short_item_type: ShortItemType, item_tag: u8, data: u32, data_width: DataWidth) -> Result<DeadOrAlive<()>, ReportParseError>
	{
		use ShortItemType::*;
		
		match short_item_type
		{
			Main =>
			{
				use ReservedMainItemTag::*;
				let report = match item_tag
				{
					0b0000 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _0),
					
					0b0001 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _1),
					
					0b0010 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _2),
					
					0b0011 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _3),
					
					0b0100 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _4),
					
					0b0101 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _5),
					
					0b0110 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _6),
					
					0b0111 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _7),
					
					0b1000 => Report::parse_input(data, self.finish_globals_and_locals_as_report_items()?),
					
					0b1001 => Report::parse_output(data, self.finish_globals_and_locals_as_report_items()?),
					
					0b1011 => Report::parse_feature(data, self.finish_globals_and_locals_as_report_items()?),
					
					0b1010 =>
					{
						use CollectionDescription::*;
						let collection_report_items = self.finish_globals_and_locals_as_collection_report_items()?;
						self.collection_stack.push_value
						(
							CollectionMainItem::new
							(
								collection_report_items,
								
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
						)?;
						
						return Ok(Alive(()))
					}
					
					0b1100 =>
					{
						use CollectionParseError::*;
						let collection = self.collection_stack.pop().ok_or(TooManyCollectionPops)?;
						if unlikely!(data != 0)
						{
							Err(EndCollectionCanNotHaveData { data: new_non_zero_u32(data) })?
						}
						Report::Collection(collection)
					}
					0b1101 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _8),
					
					0b1110 => Report::parse_reserved(data, data_width, self.finish_globals_and_locals_as_report_items()?, _9),
					
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
					
					0b0001 => self.globals()?.parse_logical_minimum(data, data_width),
					
					0b0010 => self.globals()?.parse_logical_maximum(data, data_width),
					
					0b0011 => self.globals()?.parse_physical_minimum(data, data_width),
					
					0b0100 => self.globals()?.parse_physical_maximum(data, data_width),
					
					0b0101 => self.globals()?.parse_unit_exponent(data, data_width),
					
					0b0110 => self.globals()?.parse_unit(data),
					
					0b0111 => self.globals()?.parse_report_size(data)?,
					
					0b1000 => self.globals()?.parse_report_identifier(data)?,
					
					0b1001 => self.globals()?.parse_report_count(data)?,
					
					0b1010 => self.push_globals(data, data_width)?,
					
					0b1011 => self.pop_globals(data, data_width)?,
					
					0b1100 => self.globals()?.parse_reserved0(data, data_width),
					
					0b1101 => self.globals()?.parse_reserved1(data, data_width),
					
					0b1110 => self.globals()?.parse_reserved2(data, data_width),
					
					0b1111 => unreachable!("Long tag"),
					
					_ => unreachable!(),
				}
			},
			
			Local =>
			{
				use ReservedLocalItemTag::*;
				
				const EndDelimiter: u32 = 0;
				const StartDelimiter: u32 = 1;
				
				use DelimitedLocalItemParseError::*;
				
				#[inline(always)]
				const fn error(error: DelimitedLocalItemParseError) -> Result<(), LocalItemParseError>
				{
					Err(LocalItemParseError::Delimited(error))
				}
				
				if unlikely!(self.locals_alternate_usages.is_some())
				{
					#[inline(always)]
					fn use_locals_alternate_usages(locals_alternate_usages: &mut Option<ParsingUsagesLocalItems>, data: u32, data_width: DataWidth, callback: impl FnOnce(&mut ParsingUsagesLocalItems, u32, DataWidth) -> Result<(), LocalItemParseError>) -> Result<(), LocalItemParseError>
					{
						let as_mut = locals_alternate_usages.as_mut();
						let locals_alternate_usages = unsafe { as_mut.unwrap_unchecked() };
						callback(locals_alternate_usages, data, data_width)
					}
					
					match item_tag
					{
						0b0000 => use_locals_alternate_usages(&mut self.locals_alternate_usages, data, data_width, ParsingUsagesLocalItems::parse_usage)?,
						
						0b0001 => use_locals_alternate_usages(&mut self.locals_alternate_usages, data, data_width, ParsingUsagesLocalItems::parse_usage_minimum)?,
						
						0b0010 => use_locals_alternate_usages(&mut self.locals_alternate_usages, data, data_width, ParsingUsagesLocalItems::parse_usage_maximum)?,
						
						0b0011 => error(Designator)?,
						
						0b0100 => error(DesignatorMinimum)?,
						
						0b0101 => error(DesignatorMaximum)?,
						
						0b0110 => error(Reserved(_0))?,
						
						0b0111 => error(String)?,
						
						0b1000 => error(StringMinimum)?,
						
						0b1001 => error(StringMaximum)?,
						
						0b1010 => match data
						{
							StartDelimiter => error(NestedDelimitersAreNotPermitted)?,
							
							EndDelimiter =>
							{
								let take = self.locals_alternate_usages.take();
								let alternate_usage = unsafe { take.unwrap_unchecked() };
								self.locals.push_alternate_usage(alternate_usage)?
							}
							
							_ => error(InvalidLocalDelimiter { data })?,
						},
						
						0b1011 => error(Reserved(_1))?,
						
						0b1100 => error(Reserved(_2))?,
						
						0b1101 => error(Reserved(_3))?,
						
						0b1110 => error(Reserved(_4))?,
						
						0b1111 => unreachable!("Long tag"),
						
						_ => unreachable!(),
					}
				}
				else
				{
					match item_tag
					{
						0b0000 => self.locals.parse_usage(data, data_width)?,
						
						0b0001 => self.locals.parse_usage_minimum(data, data_width)?,
						
						0b0010 => self.locals.parse_usage_maximum(data, data_width)?,
						
						0b0011 => self.locals.parse_designator(data)?,
						
						0b0100 => self.locals.parse_designator_minimum(data)?,
						
						0b0101 => self.locals.parse_designator_maximum(data)?,
						
						0b0110 => self.locals.parse_reserved(data, data_width, _0)?,
						
						0b0111 =>
						{
							let device_connection = self.device_connection;
							return Ok(self.locals.parse_string(data, device_connection)?)
						},
						
						0b1000 => self.locals.parse_string_minimum(data)?,
						
						0b1001 =>
						{
							let device_connection = self.device_connection;
							return Ok(self.locals.parse_string_maximum(data, device_connection)?)
						},
						
						0b1010 => match data
						{
							StartDelimiter =>
							{
								self.locals_alternate_usages = Some(ParsingUsagesLocalItems::default());
							},
							
							EndDelimiter => error(EndDelimiterNotPreceededByStartDelimiter)?,
							
							_ => error(InvalidLocalDelimiter { data })?,
						},
						
						0b1011 => self.locals.parse_reserved(data, data_width, _1)?,
						
						0b1100 => self.locals.parse_reserved(data, data_width, _2)?,
						
						0b1101 => self.locals.parse_reserved(data, data_width, _3)?,
						
						0b1110 => self.locals.parse_reserved(data, data_width, _4)?,
						
						0b1111 => unreachable!("Long tag"),
						
						_ => unreachable!(),
					}
				}
				
			},
		}
		
		Ok(Alive(()))
	}
	
	#[inline(always)]
	fn get_short_item_data(descriptor_bytes: &[u8], bSize: u8) -> Result<(usize, u32, DataWidth), ReportParseError>
	{
		use DataWidth::*;
		
		const inclusive_start_of_data_index: u8 = 1;
		let data_width: DataWidth = unsafe { transmute(bSize) };
		let (exclusive_end_of_data_index, data) = match data_width
		{
			Widthless =>
			{
				let exclusive_end_of_data_index = Self::get_exclusive_end_of_data_index(descriptor_bytes, inclusive_start_of_data_index, 0)?;
				(exclusive_end_of_data_index, 0)
			}
			
			EightBit =>
			{
				let (exclusive_end_of_data_index, short_item_data) = Self::get_item_data(descriptor_bytes, inclusive_start_of_data_index, 1)?;
				(exclusive_end_of_data_index, short_item_data.u8(0) as u32)
			}
			
			SixteenBit =>
			{
				let (exclusive_end_of_data_index, short_item_data) = Self::get_item_data(descriptor_bytes, inclusive_start_of_data_index, 2)?;
				(exclusive_end_of_data_index, short_item_data.u16(0) as u32)
			}
			
			ThirtyTwoBit =>
			{
				// Yes, this is correct.
				const Four: u8 = 4;
				let (exclusive_end_of_data_index, short_item_data) = Self::get_item_data(descriptor_bytes, inclusive_start_of_data_index, Four)?;
				(exclusive_end_of_data_index, short_item_data.u32(0))
			}
		};
		
		Ok((exclusive_end_of_data_index, data, data_width))
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
		if unlikely!(exclusive_end_of_data_index > descriptor_bytes.len())
		{
			return Err(ReportParseError::ItemHasDataSizeExceedingRemainingBytes { size })
		}
		Ok(exclusive_end_of_data_index)
	}
	
	#[inline(always)]
	fn get_report_descriptor_bytes<'b>(&self, reusable_buffer: &'b mut ReusableBuffer, interface_number: InterfaceNumber, report_total_length: u16) -> Result<DeadOrAlive<&'b [u8]>, ReportParseError>
	{
		use ReportParseError::*;
		
		let dead_or_alive = get_human_interface_device_report_interface_descriptor(self.device_connection.device_handle_non_null(), interface_number, reusable_buffer.as_maybe_uninit_slice_of_length(report_total_length)).map_err(GetDescriptor)?;
		match return_ok_if_dead!(dead_or_alive)
		{
			None => Err(UnsupportedEvenThoughThisIsAHumanInterfaceDevice),
			
			Some(descriptor_bytes) => Ok(Alive(descriptor_bytes)),
		}
	}
	
	#[inline(always)]
	fn current_collection(&mut self) -> &mut CollectionMainItem
	{
		self.collection_stack.current()
	}
	
	#[inline(always)]
	fn finish_globals_and_locals_as_report_items(&mut self) -> Result<ReportItems, ReportParseError>
	{
		let (usage_page, logical_extent, physical_extent, physical_unit, report_size, report_count, report_bit_length, report_identifier, global_reserved0, global_reserved1, global_reserved2) =
		{
			let parsing_globals = self.current_globals();
			parsing_globals.finish_parsing()?
		};
		
		let (usages, designators, strings, local_reserveds, longs, alternate_usages) = self.consume_and_finish_parsing_locals(usage_page)?;
		
		Ok
		(
			ReportItems
			{
				usages,
				
				alternate_usages,
				
				report_identifier,
			
				report_size,
			
				report_count,
				
				report_bit_length,
				
				logical_extent,
			
				physical_extent,
			
				physical_unit,
			
				designators,
			
				strings,
			
				global_reserved0,
			
				global_reserved1,
			
				global_reserved2,
			
				local_reserveds,
			
				longs,
			}
		)
	}
	
	#[inline(always)]
	fn finish_globals_and_locals_as_collection_report_items(&mut self) -> Result<CollectionReportItems, ReportParseError>
	{
		let (usage_page, global_reserved0, global_reserved1, global_reserved2) =
		{
			let parsing_globals = self.current_globals();
			parsing_globals.finish_collection_parsing()?
		};
		
		let (usages, designators, strings, local_reserveds, longs, alternate_usages) = self.consume_and_finish_parsing_locals(usage_page)?;
		
		Ok
		(
			CollectionReportItems
			{
				usages,
				
				alternate_usages,
				
				designators,
				
				strings,
				
				global_reserved0,
				
				global_reserved1,
				
				global_reserved2,
				
				local_reserveds,
				
				longs,
			}
		)
	}
	
	#[inline(always)]
	fn consume_and_finish_parsing_locals(&mut self, usage_page: UsagePage) -> Result<(Vec<Usage>, Vec<InclusiveRange<DesignatorIndex>>, Vec<Option<LocalizedStrings>>, Vec<ReservedLocalItem>, Vec<LongItem>, Vec<Vec<Usage>>), ReportParseError>
	{
		let parsing_locals = self.consume_locals()?;
		parsing_locals.finish_parsing(usage_page)
	}
	
	#[inline(always)]
	fn consume_locals(&mut self) -> Result<ParsingLocalItems, LocalItemParseError>
	{
		if unlikely!(self.locals_alternate_usages.is_some())
		{
			Err(DelimitedLocalItemParseError::DelimitersNotEnded)?
		}
		Ok(take(&mut self.locals))
	}
	
	#[inline(always)]
	fn globals(&mut self) -> Result<&mut ParsingGlobalItems, ReportParseError>
	{
		Self::make_mut(self.current_globals())
	}
	
	// Memory-allocation failure handling version of Rc::make_mut() which uses a less efficient path if there is one strong reference and multiple weak references; this is because it it not possible to access the necessary internal functionality.
	#[inline(always)]
	fn make_mut(this: &mut Rc<ParsingGlobalItems>) -> Result<&mut ParsingGlobalItems, ReportParseError>
	{
		#[inline(always)]
		fn new_rc() -> Result<Rc<MaybeUninit<ParsingGlobalItems>>, GlobalItemParseError>
		{
			Rc::try_new_uninit().map_err(GlobalItemParseError::CouldNotAllocateGlobals)
		}
		
		#[inline(always)]
		fn get_mut_checked<Contents>(rc: &mut Rc<Contents>) -> &mut Contents
		{
			unsafe { Rc::get_mut_unchecked(rc) }
		}
		
		// Creates a new Rc with a separate memory allocation and clones its contents.
		// Then assigns this new rc to the original's memory pointer.
		#[inline(always)]
		fn clone_rc_and_its_contents(this: &mut Rc<ParsingGlobalItems>) -> Result<(), ReportParseError>
		{
			let mut rc = new_rc()?;
			let data = get_mut_checked(&mut rc);
			{
				let data_mut_pointer = data.as_mut_ptr();
				let clone = this.deref().deref().clone();
				unsafe { data_mut_pointer.write(clone) };
			}
			*this = unsafe { rc.assume_init() };
			Ok(())
		}
		
		// More than one strong reference.
		if Rc::strong_count(this) != 1
		{
			clone_rc_and_its_contents(this)?
		}
		// One strong reference and more than one weak reference.
		else if Rc::weak_count(this) > 0
		{
			// We can not access the necessary Rc functionality as it is private, so we fallback to a clone of the contents; the original make_mut() code uses a more efficient copy of the contents and disassociated the weak references.
			clone_rc_and_its_contents(this)?
		}
		// Unique, no need to do anything.
		else
		{
		}
		
		Ok(get_mut_checked(this))
	}
	
	#[inline(always)]
	fn push_globals(&mut self, data: u32, data_width: DataWidth) -> Result<(), ReportParseError>
	{
		if unlikely!(data_width != DataWidth::Widthless)
		{
			return Err(ReportParseError::PushCanNotHaveData { data, data_width })
		}
		
		let clone = self.current_globals().clone();
		self.globals_stack.push_value(clone)?;
		Ok(())
	}
	
	#[inline(always)]
	fn pop_globals(&mut self, data: u32, data_width: DataWidth) -> Result<(), ReportParseError>
	{
		if unlikely!(data_width != DataWidth::Widthless)
		{
			return Err(ReportParseError::PopCanNotHaveData { data, data_width })
		}
		
		if self.globals_stack.pop().is_some()
		{
			Ok(())
		}
		else
		{
			Err(ReportParseError::GlobalItemParse(GlobalItemParseError::TooManyStackPops))
		}
	}
	
	#[inline(always)]
	fn current_globals(&mut self) -> &mut Rc<ParsingGlobalItems>
	{
		self.globals_stack.current()
	}
}
