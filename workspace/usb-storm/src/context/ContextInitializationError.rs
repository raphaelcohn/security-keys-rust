// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A context initialization error.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum ContextInitializationError
{
	CouldNotAllocateMemoryInRust(AllocError),
	
	InputOutputError,
	
	AccessDenied,
	
	NoDevice,
	
	RequestedResourceNotFound,
	
	TimedOut,
	
	BufferOverflow,
	
	Pipe,
	
	OutOfMemoryInLibusb,
	
	NotSupported,
	
	Other,
}

impl Display for ContextInitializationError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ContextInitializationError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ContextInitializationError::*;
		
		match self
		{
			CouldNotAllocateMemoryInRust(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<AllocError> for ContextInitializationError
{
	#[inline(always)]
	fn from(cause: AllocError) -> Self
	{
		ContextInitializationError::CouldNotAllocateMemoryInRust(cause)
	}
}
