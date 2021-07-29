// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A control transfer error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum GetStringDescriptorError
{
	GetDescriptor(GetDescriptorError),
}

impl Display for GetStringDescriptorError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetStringDescriptorError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::GetStringDescriptorError::*;
		
		match self
		{
			GetDescriptor(cause) => Some(cause),
		}
	}
}

impl From<GetDescriptorError> for GetStringDescriptorError
{
	#[inline(always)]
	fn from(cause: GetDescriptorError) -> Self
	{
		GetStringDescriptorError::GetDescriptor(cause)
	}
}
