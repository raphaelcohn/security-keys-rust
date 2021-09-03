// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum ParsedLocalItemParseError
{
	#[allow(missing_docs)]
	CouldNotPushUsageItem(TryReserveError),
	
	#[allow(missing_docs)]
	UsageMinimumCanNotBeFollowedByUsageMinimum,
	
	#[allow(missing_docs)]
	UsageMaximumMustBePreceededByUsageMinimum,
	
	#[allow(missing_docs)]
	UsageMinimumMustBeLessThanMaximum,
	
	#[allow(missing_docs)]
	UsageMinimumNotFollowedByUsageMaximum,
	
	#[allow(missing_docs)]
	UsageMinimumAndMaximumMustBeTheSameWidth,
	
	#[allow(missing_docs)]
	CouldNotPushDesignatorItem(TryReserveError),
	
	#[allow(missing_docs)]
	DesignatorMinimumCanNotBeFollowedByDesignatorMinimum,
	
	#[allow(missing_docs)]
	DesignatorMaximumMustBePreceededByDesignatorMinimum,
	
	#[allow(missing_docs)]
	DesignatorMinimumMustBeLessThanMaximum,
	
	#[allow(missing_docs)]
	DesignatorMinimumNotFollowedByDesignatorMaximum,
	
	#[allow(missing_docs)]
	CouldNotPushStringItem(TryReserveError),
	
	#[allow(missing_docs)]
	StringMinimumCanNotBeFollowedByStringMinimum,
	
	#[allow(missing_docs)]
	StringMaximumMustBePreceededByStringMinimum,
	
	#[allow(missing_docs)]
	StringMinimumMustBeLessThanMaximum,
	
	#[allow(missing_docs)]
	StringMinimumNotFollowedByStringMaximum,
	
	#[allow(missing_docs)]
	StringDescriptorIndexOutOfRange
	{
		data: u32,
	},
	
	#[allow(missing_docs)]
	CouldNotFindString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	CouldNotPushReservedItem(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForLongItemData(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotPushLongItem(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotPushSet(TryReserveError),
}

impl Display for ParsedLocalItemParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ParsedLocalItemParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ParsedLocalItemParseError::*;
		
		match self
		{
			CouldNotPushUsageItem(cause) => Some(cause),
			
			CouldNotPushDesignatorItem(cause) => Some(cause),
			
			CouldNotPushStringItem(cause) => Some(cause),
			
			CouldNotFindString(cause) => Some(cause),
			
			CouldNotPushReservedItem(cause) => Some(cause),
			
			CouldNotAllocateMemoryForLongItemData(cause) => Some(cause),
			
			CouldNotPushLongItem(cause) => Some(cause),
			
			CouldNotPushSet(cause) => Some(cause),
			
			_ => None,
		}
	}
}
