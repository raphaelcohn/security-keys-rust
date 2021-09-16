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

impl Report
{
	#[inline(always)]
	fn parse_input(data: u32, items: ReportItems) -> Self
	{
		Report::Input(InputMainItem::parse(data, items))
	}
	
	#[inline(always)]
	fn parse_output(data: u32, items: ReportItems) -> Self
	{
		Report::Output(OutputOrFeatureMainItem::parse(data, items))
	}
	
	#[inline(always)]
	fn parse_feature(data: u32, items: ReportItems) -> Self
	{
		Report::Feature(OutputOrFeatureMainItem::parse(data, items))
	}
	
	#[inline(always)]
	fn parse_reserved(data: u32, data_width: DataWidth, items: ReportItems, tag: ReservedMainItemTag) -> Self
	{
		Report::Reserved(ReservedMainItem::parse(data, data_width, items, tag))
	}
}
