// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ReportParseError
{
	#[allow(missing_docs)]
	GetDescriptor(GetDescriptorError),
	
	#[allow(missing_docs)]
	UnsupportedEvenThoughThisIsAHumanInterfaceDevice,
	
	#[allow(missing_docs)]
	LongItemTooShort,
	
	#[allow(missing_docs)]
	ItemHasDataSizeExceedingRemainingBytes
	{
		size: u8,
	},
	
	#[allow(missing_docs)]
	OutOfMemoryPushingMainItem(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateGlobals(#[serde(with = "AllocErrorRemote")] AllocError),
	
	#[allow(missing_docs)]
	OutOfStackMemory(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	GlobalItemParse(GlobalItemParseError),
	
	#[allow(missing_docs)]
	LocalItemParse(LocalItemParseError),
	
	#[allow(missing_docs)]
	NestedDelimitersAreNotPermitted,
	
	#[allow(missing_docs)]
	EndDelimiterNotPreceededByStartDelimiter,
	
	#[allow(missing_docs)]
	DelimitersNotEnded,
	
	#[allow(missing_docs)]
	InvalidLocalDelimiter
	{
		data: u32,
	},
	
	#[allow(missing_docs)]
	OpenNestedStructures,
	
	#[allow(missing_docs)]
	TooManyCollectionPops,
	
	#[allow(missing_docs)]
	EndCollectionCanNotHaveData
	{
		data: NonZeroU32,
	},
	
	#[allow(missing_docs)]
	PushCanNotHaveData
	{
		data: u32,
	
		data_width: DataWidth,
	},
	
	#[allow(missing_docs)]
	PopCanNotHaveData
	{
		data: u32,
		
		data_width: DataWidth,
	},
	
	#[allow(missing_docs)]
	CouldNotFinishParsingAlternateUsage(LocalItemParseError),
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
			
			CouldNotFinishParsingAlternateUsage(cause) => Some(cause),
			
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

impl From<LocalItemParseError> for ReportParseError
{
	#[inline(always)]
	fn from(cause: LocalItemParseError) -> Self
	{
		ReportParseError::LocalItemParse(cause)
	}
}
