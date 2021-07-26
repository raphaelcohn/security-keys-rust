// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A simple error.
#[derive(Debug)]
pub enum SimpleSerializerError
{
	/// Custom.
	Custom(String),

	/// Input/Output.
	Io(io::Error),
}

impl Display for SimpleSerializerError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SimpleSerializerError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::SimpleSerializerError::*;
		
		match self
		{
			Io(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl ser::Error for SimpleSerializerError
{
	#[inline(always)]
	fn custom<T: Display>(msg: T) -> Self
	{
		SimpleSerializerError::Custom(format!("{}", msg))
	}
}

impl From<io::Error> for SimpleSerializerError
{
	#[inline(always)]
	fn from(cause: io::Error) -> Self
	{
		SimpleSerializerError::Io(cause)
	}
}
