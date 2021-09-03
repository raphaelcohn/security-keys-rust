// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report reserved main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedMainItem
{
	globals: Rc<GlobalItems>,
	
	locals: LocalItems,

	tag: ReservedMainItemTag,

	value: u32,
	
	was_32_bits_wide: bool,
}

impl MainItem for ReservedMainItem
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

impl ReservedMainItem
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn tag(&self) -> ReservedMainItemTag
	{
		self.tag
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn value(&self) -> u32
	{
		self.value
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn was_32_bits_wide(&self) -> bool
	{
		self.was_32_bits_wide
	}
}
