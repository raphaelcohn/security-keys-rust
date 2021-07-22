// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ActivityError
{
	CardReaderName(CardReaderNameError),
	
	EstablishContext
	{
		cause: CommunicationError,
	
		scope: Scope,
	},
	
	InitialCardReaderStates(CardReaderStatusChangeError),
	
	ConnectedCardReaders(CommunicationError),
	
	UpdateCardReaderStates(CardReaderStatusChangeError),

	ConnectCard(ConnectCardError),
	
	CardStatus(WithDisconnectError<CardStatusError>),
	
	BeginTransaction(WithDisconnectError<TransactionError>),
	
	GetAttribute
	{
		cause: WithDisconnectError<CardTransmissionError>,
	
		attribute_identifier: AttributeIdentifier,
	},
	
	SetAttribute
	{
		cause: WithDisconnectError<CardTransmissionError>,
	
		attribute_identifier: AttributeIdentifier,
	},
	
	TransmitApplicationProtocolDataUnit
	{
		cause: WithDisconnectError<CardCommandError>,
	
		/// `CLA`.
		class: u8,
	
		/// `INS`.
		instruction: u8,
	
		/// `P1-P2`.
		parameters: [u8; 2],
	},
	
	TransmitControl
	{
		cause: WithDisconnectError<CardCommandError>,
		
		control_code: ControlCode,
	},
	
	EndTransaction
	{
		cause: WithDisconnectError<TransactionError>,
	
		end_transaction_disposition: CardDisposition,
	},
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
			CardReaderName(cause) => Some(cause),
			
			EstablishContext { cause, .. } => Some(cause),
			
			InitialCardReaderStates(cause) => Some(cause),
			
			ConnectedCardReaders(cause) => Some(cause),
			
			UpdateCardReaderStates(cause) => Some(cause),
			
			ConnectCard(cause) => Some(cause),
			
			CardStatus(cause) => Some(cause),
			
			BeginTransaction(cause) => Some(cause),
			
			GetAttribute { cause, .. } => Some(cause),
			
			SetAttribute { cause, .. } => Some(cause),
			
			TransmitApplicationProtocolDataUnit { cause, .. } => Some(cause),
			
			TransmitControl { cause, .. } => Some(cause),
			
			EndTransaction { cause, .. } => Some(cause),
		}
	}
}

impl From<CardReaderNameError> for ActivityError
{
	#[inline(always)]
	fn from(cause: CardReaderNameError) -> Self
	{
		ActivityError::CardReaderName(cause)
	}
}
