// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LocalItemParseError
{
	#[allow(missing_docs)]
	UsageParse(UsageParseError),
	
	#[allow(missing_docs)]
	DesignatorParse(DesignatorParseError),
	
	#[allow(missing_docs)]
	StringParse(StringParseError),
	
	#[allow(missing_docs)]
	LongItemParse(LongItemParseError),
	
	#[allow(missing_docs)]
	AlternateUsageParse(AlternateUsageParseError),
	
	#[allow(missing_docs)]
	CouldNotPushReservedItem(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	Delimited(DelimitedLocalItemParseError),
}

impl Display for LocalItemParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for LocalItemParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use LocalItemParseError::*;
		
		match self
		{
			UsageParse(cause) => Some(cause),
			
			DesignatorParse(cause) => Some(cause),
			
			StringParse(cause) => Some(cause),
			
			LongItemParse(cause) => Some(cause),
			
			CouldNotPushReservedItem(cause) => Some(cause),
			
			AlternateUsageParse(cause) => Some(cause),
			
			Delimited(cause) => Some(cause),
		}
	}
}

impl From<UsageParseError> for LocalItemParseError
{
	#[inline(always)]
	fn from(cause: UsageParseError) -> Self
	{
		LocalItemParseError::UsageParse(cause)
	}
}

impl From<DesignatorParseError> for LocalItemParseError
{
	#[inline(always)]
	fn from(cause: DesignatorParseError) -> Self
	{
		LocalItemParseError::DesignatorParse(cause)
	}
}

impl From<StringParseError> for LocalItemParseError
{
	#[inline(always)]
	fn from(cause: StringParseError) -> Self
	{
		LocalItemParseError::StringParse(cause)
	}
}

impl From<LongItemParseError> for LocalItemParseError
{
	#[inline(always)]
	fn from(cause: LongItemParseError) -> Self
	{
		LocalItemParseError::LongItemParse(cause)
	}
}

impl From<AlternateUsageParseError> for LocalItemParseError
{
	#[inline(always)]
	fn from(cause: AlternateUsageParseError) -> Self
	{
		LocalItemParseError::AlternateUsageParse(cause)
	}
}

impl From<DelimitedLocalItemParseError> for LocalItemParseError
{
	#[inline(always)]
	fn from(cause: DelimitedLocalItemParseError) -> Self
	{
		LocalItemParseError::Delimited(cause)
	}
}
