// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LogicalExtentParseError
{
	#[allow(missing_docs)]
	LogicalExtentMaximumMissing
	{
		minimum: i32,
	},
	
	#[allow(missing_docs)]
	LogicalExtentMinimumMissing
	{
		maximum: i32,
	},
	
	#[allow(missing_docs)]
	LogicalExtentMinimumAndMaximumMissing,
	
	#[allow(missing_docs)]
	MinimumLogicalExtentExceedsMaximum
	{
		minimum: i32,
		
		maximum: i32,
	},
	
	#[allow(missing_docs)]
	LogicalMinimumRequiresMoreBitsThanReportSize
	{
		minimum: i32,
		
		report_size: ReportSize,
	},
	
	#[allow(missing_docs)]
	LogicalMaximumRequiresMoreBitsThanReportSize
	{
		maximum: i32,
		
		report_size: ReportSize,
	},
}

impl Display for LogicalExtentParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for LogicalExtentParseError
{
}
