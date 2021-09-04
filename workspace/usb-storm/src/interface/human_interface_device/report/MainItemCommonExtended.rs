// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report input main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MainItemCommonExtended
{
	#[serde(flatten)]
	common: MainItemCommon,
	
	volatile: bool,
}

impl MainItem for MainItemCommonExtended
{
	#[inline(always)]
	fn globals(&self) -> &GlobalItems
	{
		self.common.globals()
	}
	
	#[inline(always)]
	fn locals(&self) -> &LocalItems
	{
		self.common.locals()
	}
}

impl MainItemCommonExtended
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn volatile(&self) -> bool
	{
		self.volatile
	}
	
	#[inline(always)]
	fn parse(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Self
		{
			common: MainItemCommon::parse(data, globals, locals),
		
			volatile: (data & 0b0_1000_0000) != 0,
		}
	}
}
