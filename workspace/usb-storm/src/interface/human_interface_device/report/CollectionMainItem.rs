// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report collection main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionMainItem
{
	common: CollectionCommon,
	
	description: CollectionDescription,
	
	end_data: u32,
}

impl Default for CollectionMainItem
{
	#[inline(always)]
	fn default() -> Self
	{
		const ValueIrrelevantAsWillBeRemovedWhenParsingFinished: CollectionDescription = CollectionDescription::Application;
		Self::new(Default::default(), Default::default(), ValueIrrelevantAsWillBeRemovedWhenParsingFinished)
	}
}

impl MainItem for CollectionMainItem
{
	#[inline(always)]
	fn globals(&self) -> &GlobalItems
	{
		&self.common.globals()
	}
	
	#[inline(always)]
	fn locals(&self) -> &LocalItems
	{
		&self.common.locals()
	}
}

impl Deref for CollectionMainItem
{
	type Target = [Report];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.common.deref()
	}
}

impl CollectionMainItem
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> CollectionDescription
	{
		self.description
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn end_data(&self) -> u32
	{
		self.end_data
	}
	
	#[inline(always)]
	fn new(globals: Rc<GlobalItems>, locals: LocalItems, description: CollectionDescription) -> Self
	{
		Self
		{
			common: CollectionCommon
			{
				globals,
				
				locals,
				
				reports: Vec::new(),
			},
		
			description,
		
			end_data: 0,
		}
	}
	
	#[inline(always)]
	fn push_report(&mut self, item: Report) -> Result<(), ReportParseError>
	{
		self.0.try_push(item).map_err(ReportParseError::OutOfMemoryPushingMainItem)
	}
}
