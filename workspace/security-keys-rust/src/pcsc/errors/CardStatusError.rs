// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CardStatusError
{
	TooManyResets,
	
	ReconnectionUnavailableOrCommunication(ReconnectionUnavailableOrCommunicationError),
}

impl Display for CardStatusError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CardStatusError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Self::*;
		
		match self
		{
			ReconnectionUnavailableOrCommunication(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<ConnectCardError> for CardStatusError
{
	#[inline(always)]
	fn from(cause: ConnectCardError) -> Self
	{
		CardStatusError::ReconnectionUnavailableOrCommunication(ReconnectionUnavailableOrCommunicationError::Reconnection(cause))
	}
}
