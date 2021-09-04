// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A top-level report.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionCommon
{
	#[serde(flatten)]
	globals: Rc<GlobalItems>,
	
	#[serde(flatten)]
	locals: LocalItems,
	
	reports: Vec<Report>,
}

impl Deref for CollectionCommon
{
	type Target = [Report];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.reports
	}
}

impl MainItem for CollectionCommon
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

impl CollectionCommon
{
	#[inline(always)]
	fn push_report(&mut self, item: Report) -> Result<(), ReportParseError>
	{
		self.reports.try_push(item).map_err(ReportParseError::OutOfMemoryPushingMainItem)
	}
}
