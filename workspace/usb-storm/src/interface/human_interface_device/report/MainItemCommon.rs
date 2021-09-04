// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report input main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MainItemCommon
{
	globals: Rc<GlobalItems>,
	
	locals: LocalItems,
	
	constant_rather_than_data: bool,

	relative_rather_than_absolute: bool,
	
	wrap: bool,
	
	non_linear: bool,

	no_preferred_state: bool,

	has_null_state: bool,

	buffered_bytes_rather_than_bit_field: bool,
}

impl MainItem for MainItemCommon
{
	#[inline(always)]
	fn globals(&self) -> &GlobalItems
	{
		&self.globals
	}
	
	#[inline(always)]
	fn locals(&self) -> &LocalItems
	{
		&self.locals
	}
}

impl MainItemCommon
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn constant_rather_than_data(&self) -> bool
	{
		self.constant_rather_than_data
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn relative_rather_than_absolute(&self) -> bool
	{
		self.relative_rather_than_absolute
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn wrap(&self) -> bool
	{
		self.wrap
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn non_linear(&self) -> bool
	{
		self.non_linear
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn no_preferred_state(&self) -> bool
	{
		self.no_preferred_state
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn has_null_state(&self) -> bool
	{
		self.has_null_state
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn buffered_bytes_rather_than_bit_field(&self) -> bool
	{
		self.buffered_bytes_rather_than_bit_field
	}
	
	#[inline(always)]
	fn parse(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Self
		{
			globals,
		
			locals,
			
			constant_rather_than_data: (data & 0b0_0000_0001) != 0,
			
			relative_rather_than_absolute: (data & 0b0_0000_0010) != 0,
			
			wrap: (data & 0b0_0000_0100) != 0,
			
			non_linear: (data & 0b0_0000_1000) != 0,
			
			no_preferred_state: (data & 0b0_0001_0000) != 0,
			
			has_null_state: (data & 0b0_0100_0000) != 0,
			
			buffered_bytes_rather_than_bit_field: (data & 0b1_0000_0000) != 0,
		}
	}
}
