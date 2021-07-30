// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Card reader name error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CardReaderNameError
{
	/// A reader name may not be an empty C string.
	Empty,

	/// A reader name may not exceed 128 bytes, including the trailing ASCII NULL.
	TooLong(usize),

	/// When constructing from bytes, the bytes contained an ASCII NUL.
	Nul(NulError),
}

impl Display for CardReaderNameError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CardReaderNameError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use CardReaderNameError::*;
		
		match self
		{
			Nul(cause) => Some(cause),
			
			_ => None,
		}
	}
}
