// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum GlobalItemParseError
{
	#[allow(missing_docs)]
	UsagePageCanNotBeZero,
	
	#[allow(missing_docs)]
	UsagePageTooBig
	{
		data: u32
	},
	
	#[allow(missing_docs)]
	ReportIdentifierZeroIsReserved,
	
	#[allow(missing_docs)]
	ReportIdentifierTooLarge
	{
		data: u32,
	},
	
	#[allow(missing_docs)]
	ReportCountCanNotBeZero,
	
	#[allow(missing_docs)]
	ReportCountTooLarge
	{
		data: u32,
	},
	
	#[allow(missing_docs)]
	CouldNotPushStack(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	TooManyStackPops,
	
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
	
	#[allow(missing_docs)]
	MinimumPhysicalExtentExceedsMaximum
	{
		minimum: i32,
		
		maximum: i32,
	},
	
	#[allow(missing_docs)]
	PhysicalExtentWouldCauseDivisionByZeroForResolution,
	
	#[allow(missing_docs)]
	NoReportSize,
	
	#[allow(missing_docs)]
	NoReportCount,
	
	#[allow(missing_docs)]
	NoUsagePage,
	
	#[allow(missing_docs)]
	ReportBitLengthIsTooLarge
	{
		report_bit_length: NonZeroU32,
	},
	
	#[allow(missing_docs)]
	ReportSizeGreaterThan256Bytes
	{
		data: u32,
	},
}

impl Display for GlobalItemParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GlobalItemParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use GlobalItemParseError::*;
		
		match self
		{
			CouldNotPushStack(cause) => Some(cause),
			
			_ => None,
		}
	}
}
