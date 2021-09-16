// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A report collection main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionMainItem
{
	description: CollectionDescription,
	
	#[serde(flatten)]
	common: CollectionCommon,
}

impl Deref for CollectionMainItem
{
	type Target = CollectionCommon;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.common
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
	pub fn items(&self) -> &CollectionReportItems
	{
		self.common.items()
	}
	
	#[inline(always)]
	fn new_for_collections_stack() -> Self
	{
		const ValueIrrelevantAsWillBeRemovedWhenParsingFinished: CollectionDescription = CollectionDescription::Application;
		Self::new(Default::default(), ValueIrrelevantAsWillBeRemovedWhenParsingFinished)
	}
	
	#[inline(always)]
	fn new(items: CollectionReportItems, description: CollectionDescription) -> Self
	{
		Self
		{
			description,
			
			common: CollectionCommon
			{
				items,
				
				reports: Vec::new(),
			},
		}
	}
	
	#[inline(always)]
	fn push_report(&mut self, item: Report) -> Result<(), ReportParseError>
	{
		self.common.push_report(item)
	}
}
