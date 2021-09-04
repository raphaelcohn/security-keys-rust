// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportParseError
{
	#[allow(missing_docs)]
	GetDescriptor(GetDescriptorError),
	
	#[allow(missing_docs)]
	UnsupportedEvenThisIsAHumanInterfaceDevice,
	
	#[allow(missing_docs)]
	LongItemTooShort,
	
	#[allow(missing_docs)]
	ItemHasDataSizeExceedingRemainingBytes
	{
		size: u8,
	},
	
	#[allow(missing_docs)]
	OutOfMemoryPushingMainItem(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateGlobals(AllocError),
	
	#[allow(missing_docs)]
	OutOfStackMemory(TryReserveError),
	
	#[allow(missing_docs)]
	GlobalItemParse(GlobalItemParseError),
	
	#[allow(missing_docs)]
	LocalItemParse(ParsedLocalItemParseError),
	
	#[allow(missing_docs)]
	ClosedTooManyOpenLocalSets,
	
	#[allow(missing_docs)]
	InvalidLocalDelimiter
	{
		data: u32,
	},
	
	#[allow(missing_docs)]
	OpenNestedStructures,
	
	#[allow(missing_docs)]
	TooManyCollectionPops,
}

impl Display for ReportParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ReportParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ReportParseError::*;
		
		match self
		{
			GetDescriptor(cause) => Some(cause),
			
			OutOfMemoryPushingMainItem(cause) => Some(cause),
			
			CouldNotAllocateGlobals(cause) => Some(cause),
			
			OutOfStackMemory(cause) => Some(cause),
			
			GlobalItemParse(cause) => Some(cause),
			
			LocalItemParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<GlobalItemParseError> for ReportParseError
{
	#[inline(always)]
	fn from(cause: GlobalItemParseError) -> Self
	{
		ReportParseError::GlobalItemParse(cause)
	}
}

impl From<ParsedLocalItemParseError> for ReportParseError
{
	#[inline(always)]
	fn from(cause: ParsedLocalItemParseError) -> Self
	{
		ReportParseError::LocalItemParse(cause)
	}
}
