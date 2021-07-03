// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum ContextError
{
	OutOfMemoryAllocatingBuffer(TryReserveError),
	
	EstablishAContextWithUserScope(pcsc::Error),
	
	ListReadersLength(pcsc::Error),
	
	ListReaders(pcsc::Error),
	
	ConnectShared(pcsc::Error),
}

impl Display for ContextError
{
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		write!(f, "{}:", self.to_string())?;
		
		use self::ContextError::*;
		match self
		{
			OutOfMemoryAllocatingBuffer(cause) => write!(f, "{}", cause),
			
			EstablishAContextWithUserScope(cause) => write!(f, "{}", cause),
			
			ListReadersLength(cause) => write!(f, "{}", cause),
			
			ListReaders(cause) => write!(f, "{}", cause),
			
			ConnectShared(cause) => write!(f, "{}", cause),
		}
	}
}

impl error::Error for ContextError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::ContextError::*;
		match self
		{
			OutOfMemoryAllocatingBuffer(cause) => Some(cause),
			
			EstablishAContextWithUserScope(cause) => Some(cause),
			
			ListReadersLength(cause) => Some(cause),
			
			ListReaders(cause) => Some(cause),
			
			ConnectShared(cause) => Some(cause),
		}
	}
}

impl From<TryReserveError> for ContextError
{
	#[inline(always)]
	fn from(cause: TryReserveError) -> Self
	{
		ContextError::OutOfMemoryAllocatingBuffer(cause)
	}
}
