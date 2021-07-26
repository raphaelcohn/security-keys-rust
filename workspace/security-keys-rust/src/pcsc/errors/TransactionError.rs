// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TransactionError
{
	SharingViolation,
	
	CardStatus(CardStatusError),
}

impl Display for TransactionError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for TransactionError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::TransactionError::*;
		
		match self
		{
			CardStatus(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<ConnectCardError> for TransactionError
{
	#[inline(always)]
	fn from(cause: ConnectCardError) -> Self
	{
		TransactionError::CardStatus(CardStatusError::ReconnectionUnavailableOrCommunication(ReconnectionUnavailableOrCommunicationError::Reconnection(cause)))
	}
}

impl From<CardStatusError> for TransactionError
{
	#[inline(always)]
	fn from(cause: CardStatusError) -> Self
	{
		TransactionError::CardStatus(cause)
	}
}

impl From<UnavailableOrCommunicationError> for TransactionError
{
	#[inline(always)]
	fn from(cause: UnavailableOrCommunicationError) -> Self
	{
		TransactionError::CardStatus(CardStatusError::ReconnectionUnavailableOrCommunication(ReconnectionUnavailableOrCommunicationError::UnavailableOrCommunication(cause)))
	}
}
