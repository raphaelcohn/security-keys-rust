// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum GlobalItemParseError
{
	#[allow(missing_docs)]
	Stack(StackError),
	
	#[allow(missing_docs)]
	CouldNotAllocateGlobals(#[serde(with = "AllocErrorRemote")] AllocError),
	
	#[allow(missing_docs)]
	TooManyStackPops,
	
	#[allow(missing_docs)]
	UsagePageParse(UsagePageParseError),
	
	#[allow(missing_docs)]
	ReportCountParse(ReportCountParseError),
	
	#[allow(missing_docs)]
	ReportSizeParse(ReportSizeParseError),
	
	#[allow(missing_docs)]
	ReportIdentifierParse(ReportIdentifierParseError),
	
	#[allow(missing_docs)]
	LogicalExtentParse(LogicalExtentParseError),
	
	#[allow(missing_docs)]
	PhysicalExtentParse(PhysicalExtentParseError),
	
	#[allow(missing_docs)]
	ReportBitLengthIsTooLarge
	{
		report_size: ReportSize,
		
		report_count: ReportCount,
		
		report_bit_length: NonZeroU32,
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
			Stack(cause) => Some(cause),
			
			CouldNotAllocateGlobals(cause) => Some(cause),
			
			UsagePageParse(cause) => Some(cause),
			
			ReportCountParse(cause) => Some(cause),
			
			ReportSizeParse(cause) => Some(cause),
			
			ReportIdentifierParse(cause) => Some(cause),
			
			LogicalExtentParse(cause) => Some(cause),
			
			PhysicalExtentParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<StackError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: StackError) -> Self
	{
		GlobalItemParseError::Stack(cause)
	}
}

impl From<UsagePageParseError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: UsagePageParseError) -> Self
	{
		GlobalItemParseError::UsagePageParse(cause)
	}
}

impl From<ReportCountParseError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: ReportCountParseError) -> Self
	{
		GlobalItemParseError::ReportCountParse(cause)
	}
}

impl From<ReportSizeParseError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: ReportSizeParseError) -> Self
	{
		GlobalItemParseError::ReportSizeParse(cause)
	}
}

impl From<ReportIdentifierParseError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: ReportIdentifierParseError) -> Self
	{
		GlobalItemParseError::ReportIdentifierParse(cause)
	}
}

impl From<LogicalExtentParseError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: LogicalExtentParseError) -> Self
	{
		GlobalItemParseError::LogicalExtentParse(cause)
	}
}

impl From<PhysicalExtentParseError> for GlobalItemParseError
{
	#[inline(always)]
	fn from(cause: PhysicalExtentParseError) -> Self
	{
		GlobalItemParseError::PhysicalExtentParse(cause)
	}
}
