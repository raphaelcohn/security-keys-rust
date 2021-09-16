// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Details common to a report's output, feature or input main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MainItemCommon
{
	#[serde(flatten)]
	items: ReportItems,
	
	data_or_constant: DataOrConstant,
	
	absolute_or_relative: AbsoluteOrRelative,
}

impl HasReportItems for MainItemCommon
{
	#[inline(always)]
	fn items(&self) -> &ReportItems
	{
		&self.items
	}
}

impl MainItemCommon
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn data_or_constant(&self) -> DataOrConstant
	{
		self.data_or_constant
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn absolute_or_relative(&self) -> AbsoluteOrRelative
	{
		self.absolute_or_relative
	}
	
	#[inline(always)]
	fn parse(data: u32, items: ReportItems) -> Self
	{
		Self
		{
			items,
			
			data_or_constant: parse_boolean_enum(data, 0),
			
			absolute_or_relative: parse_boolean_enum(data, 2),
		}
	}
}
