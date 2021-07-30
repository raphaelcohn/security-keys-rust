// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Card reader status change error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CardReaderStatusChangeError
{
	/// This *does not* occur if waiting loops internally in libpcsclite, ie you can not rely on it.
	UnknownCardReader,
	
	#[allow(missing_docs)]
	Cancelled,
	
	#[allow(missing_docs)]
	TimedOut,
	
	#[allow(missing_docs)]
	UnavailableOrCommunication(UnavailableOrCommunicationError),
}

impl Display for CardReaderStatusChangeError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CardReaderStatusChangeError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Self::*;
		
		match self
		{
			UnavailableOrCommunication(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<CommunicationError> for CardReaderStatusChangeError
{
	#[inline(always)]
	fn from(cause: CommunicationError) -> Self
	{
		CardReaderStatusChangeError::UnavailableOrCommunication(UnavailableOrCommunicationError::Communication(cause))
	}
}
