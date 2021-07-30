// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum TagParseError
{
	OutOfDataForSubsequentByte
	{
		subsequent_byte_index: u8,
	},
	
	ShiftedTooFar
	{
		subsequent_byte_index: u8,
	},
	
	FirstSubsequentByteHasLower7BitsAllZero,
}

impl Display for TagParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for TagParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Self::*;
		
		match self
		{
			OutOfDataForSubsequentByte { .. } => None,
			
			ShiftedTooFar { .. } => None,
			
			FirstSubsequentByteHasLower7BitsAllZero => None,
		}
	}
}
