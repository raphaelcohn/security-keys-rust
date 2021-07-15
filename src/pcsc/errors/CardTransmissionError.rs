// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CardTransmissionError
{
	DataExchangeWithCardFailed,
	
	CardStatus(CardStatusError),
}

impl Display for CardTransmissionError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CardTransmissionError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::CardTransmissionError::*;
		
		match self
		{
			CardStatus(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<CardStatusError> for CardTransmissionError
{
	#[inline(always)]
	fn from(cause: CardStatusError) -> Self
	{
		CardTransmissionError::CardStatus(cause)
	}
}

impl From<ConnectCardError> for CardTransmissionError
{
	#[inline(always)]
	fn from(cause: ConnectCardError) -> Self
	{
		CardTransmissionError::CardStatus(CardStatusError::ReconnectionUnavailableOrCommunication(ReconnectionUnavailableOrCommunicationError::Reconnection(cause)))
	}
}
