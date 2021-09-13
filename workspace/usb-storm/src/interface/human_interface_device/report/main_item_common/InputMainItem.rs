// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Details common to a report's input main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InputMainItem
{
	#[allow(missing_docs)]
	Variable(OutputOrFeatureOrInputVariableCommon),
	
	#[allow(missing_docs)]
	Array(MainItemCommon),
}

impl MainItem for InputMainItem
{
	#[inline(always)]
	fn globals(&self) -> &GlobalItems
	{
		use InputMainItem::*;
		
		match self
		{
			Variable(main_item) => main_item.globals(),
			
			Array(main_item) => main_item.globals(),
		}
	}
	
	#[inline(always)]
	fn locals(&self) -> &LocalItems
	{
		use InputMainItem::*;
		
		match self
		{
			Variable(main_item) => main_item.locals(),
			
			Array(main_item) => main_item.locals(),
		}
	}
}

impl InputMainItem
{
	#[inline(always)]
	pub(super) fn parse(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		use InputMainItem::*;
		if is_array(data)
		{
			Array(MainItemCommon::parse(data, globals, locals))
		}
		else
		{
			Variable(OutputOrFeatureOrInputVariableCommon::parse(data, globals, locals))
		}
	}
}
