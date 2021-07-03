// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum ActivityError
{
	Context(ContextError),
	
	NoYubicoReaderPresent,
	
	NoSmartCardPresent,
	
	Card(CardError),
}

impl Display for ActivityError
{
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ActivityError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::ActivityError::*;
		
		match self
		{
			Context(cause) => Some(cause),
			
			NoYubicoReaderPresent => None,
			
			NoSmartCardPresent => None,
			
			Card(cause) => Some(cause),
		}
	}
}

impl From<ContextError> for ActivityError
{
	#[inline(always)]
	fn from(cause: ContextError) -> Self
	{
		ActivityError::Context(cause)
	}
}

impl From<CardError> for ActivityError
{
	#[inline(always)]
	fn from(cause: CardError) -> Self
	{
		ActivityError::Card(cause)
	}
}
