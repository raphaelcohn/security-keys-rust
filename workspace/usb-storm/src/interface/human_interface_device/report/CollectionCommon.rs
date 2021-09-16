// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A top-level report.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionCommon
{
	#[serde(flatten)]
	items: CollectionReportItems,
	
	reports: Vec<Report>,
}

impl CollectionCommon
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn items(&self) -> &CollectionReportItems
	{
		&self.items
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn reports(&self) -> &[Report]
	{
		&self.reports
	}
	
	#[inline(always)]
	fn push_report(&mut self, item: Report) -> Result<(), ReportParseError>
	{
		self.reports.try_push(item).map_err(ReportParseError::OutOfMemoryPushingMainItem)
	}
}
