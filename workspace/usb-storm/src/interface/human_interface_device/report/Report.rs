// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Report
{
	#[allow(missing_docs)]
	Input(InputMainItem),
	
	#[allow(missing_docs)]
	Output(OutputOrFeatureMainItem),
	
	#[allow(missing_docs)]
	Feature(OutputOrFeatureMainItem),
	
	#[allow(missing_docs)]
	Collection(CollectionMainItem),
	
	#[allow(missing_docs)]
	Reserved(ReservedMainItem),
}

impl MainItem for Report
{
	#[inline(always)]
	fn globals(&self) -> &GlobalItems
	{
		use Report::*;
		
		match self
		{
			Input(item) => item.globals(),
			
			Output(item) => item.globals(),
			
			Feature(item) => item.globals(),
			
			Collection(item) => item.globals(),
			
			Reserved(item) => item.globals(),
		}
	}
	
	#[inline(always)]
	fn locals(&self) -> &LocalItems
	{
		use Report::*;
		
		match self
		{
			Input(item) => item.locals(),
			
			Output(item) => item.locals(),
			
			Feature(item) => item.locals(),
			
			Collection(item) => item.locals(),
			
			Reserved(item) => item.locals(),
		}
	}
}

impl Report
{
	#[inline(always)]
	fn parse_input(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Report::Input(InputMainItem::parse(data, globals, locals))
	}
	
	#[inline(always)]
	fn parse_output(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Report::Output(OutputOrFeatureMainItem::parse(data, globals, locals))
	}
	
	#[inline(always)]
	fn parse_feature(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Report::Feature(OutputOrFeatureMainItem::parse(data, globals, locals))
	}
	
	#[inline(always)]
	fn parse_reserved(data: u32, was_32_bits_wide: bool, globals: Rc<GlobalItems>, locals: LocalItems, tag: ReservedMainItemTag) -> Self
	{
		Report::Reserved
		(
			ReservedMainItem
			{
				globals,
				
				locals,
				
				tag,
				
				value: data,
				
				was_32_bits_wide
			}
		)
	}
}
