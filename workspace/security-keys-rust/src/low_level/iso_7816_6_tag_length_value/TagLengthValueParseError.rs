// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum TagLengthValueParseError
{
	Tag(TagParseError),
	
	OutOfDataForLengthFirstByte,
	
	LengthFieldEncodesValueGreaterThan65535,
	
	OutOfDataForLongLengthOf1,
	
	OutOfDataForLongLengthOf2,

	Value
	{
		length: u16,
	},
	
	OutOfMemory(TryReserveError),
}

impl Display for TagLengthValueParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for TagLengthValueParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use TagLengthValueParseError::*;
		
		match self
		{
			Tag(cause) => Some(cause),
			
			OutOfDataForLengthFirstByte => None,
			
			LengthFieldEncodesValueGreaterThan65535 => None,
			
			OutOfDataForLongLengthOf1 => None,
			
			OutOfDataForLongLengthOf2 => None,
			
			Value { .. } => None,
			
			OutOfMemory(cause) => Some(cause)
		}
	}
}

impl From<TagParseError> for TagLengthValueParseError
{
	#[inline(always)]
	fn from(cause: TagParseError) -> Self
	{
		TagLengthValueParseError::Tag(cause)
	}
}

impl From<TryReserveError> for TagLengthValueParseError
{
	#[inline(always)]
	fn from(cause: TryReserveError) -> Self
	{
		TagLengthValueParseError::OutOfMemory(cause)
	}
}
