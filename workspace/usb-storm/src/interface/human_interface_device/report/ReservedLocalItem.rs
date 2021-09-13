// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report reserved local item.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedLocalItem
{
	tag: ReservedLocalItemTag,

	data: u32,
	
	data_width: DataWidth,
}

impl TryClone for ReservedLocalItem
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(*self)
	}
}

impl ReservedLocalItem
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn tag(&self) -> ReservedLocalItemTag
	{
		self.tag
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn data(&self) -> u32
	{
		self.data
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn data_width(&self) -> DataWidth
	{
		self.data_width
	}
	
	#[inline(always)]
	fn parse(data: u32, data_width: DataWidth, tag: ReservedLocalItemTag) -> Self
	{
		Self
		{
			tag,
			
			data,
			
			data_width
		}
	}
}
