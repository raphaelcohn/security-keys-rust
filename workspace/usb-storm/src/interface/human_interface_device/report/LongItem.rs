// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report long item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LongItem
{
	tag: LongItemTag,

	data: Vec<u8>,
}

impl TryClone for LongItem
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok
		(
			Self
			{
				tag: self.tag,
			
				data: self.data.try_clone()?,
			}
		)
	}
}

impl LongItem
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn tag(&self) -> LongItemTag
	{
		self.tag
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn data(&self) -> &[u8]
	{
		&self.data
	}
	
	#[inline(always)]
	fn parse(item_tag: u8, data: &[u8]) -> Result<Self, LocalItemParseError>
	{
		Ok
		(
			Self
			{
				tag: LongItemTag::parse(item_tag),
			
				data: Vec::new_from(data).map_err(LocalItemParseError::CouldNotAllocateMemoryForLongItemData)?,
			}
		)
	}
}
