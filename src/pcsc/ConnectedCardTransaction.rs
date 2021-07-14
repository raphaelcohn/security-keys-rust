// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct ConnectedCardTransaction
{
	connected_card: ConnectedCard,
	
	disposed: bool,
}

impl Drop for ConnectedCardTransaction
{
	#[inline(always)]
	fn drop(&mut self)
	{
		assert!(self.disposed, "Transaction was not ended")
	}
}

impl ConnectedCardOrTransaction for ConnectedCardTransaction
{
	#[inline(always)]
	fn active_protocol(&self) -> Option<Protocol>
	{
		self.connected_card.active_protocol()
	}
	
	#[inline(always)]
	fn status<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(&self, card_status_user: CardStatusUser) -> Result<R, CardStatusError>
	{
		self.connected_card.status(card_status_user)
	}
}

impl ConnectedCardTransaction
{
	/// Returns `None` if the attribute is unsupported.
	///
	/// The CCID project at <https://salsa.debian.org/rousseau/CCID.git> contains a partial list of attribute value formats in [`SCARDGETATTRIB.txt`](https://salsa.debian.org/rousseau/CCID/-/blob/master/SCARDGETATTRIB.txt).
	#[inline(always)]
	pub(crate) fn get_attribute<AttributeUser: for <'a> FnOnce(&'a [u8]) -> R, R>(&self, attribute_identifier: AttributeIdentifier, attribute_user: AttributeUser) -> Result<TransactedCommandOutcome<Option<R>, ()>, CardTransmissionError>
	{
		let mut attribute_value: [MaybeUninit<u8>; MAX_BUFFER_SIZE] = MaybeUninit::uninit_array();
		
		use self::TransactedCommandOutcome::*;
		
		let mut attribute_length = MAX_BUFFER_SIZE as DWORD;
		let result = unsafe { SCardGetAttrib(self.connected_card.handle, attribute_identifier.into_DWORD(), attribute_value.as_mut_ptr() as *mut u8, &mut attribute_length) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			let slice = attribute_value.get_unchecked_range_safe(..(attribute_length as usize));
			let attribute_value = unsafe { MaybeUninit::slice_assume_init_ref(slice) };
			return Ok(Succeeded(Some(attribute_user(attribute_value))))
		}
		
		use self::CardTransmissionError::*;
		use self::ReconnectionUnavailableOrCommunicationError::*;
		use self::UnavailableOrCommunicationError::*;
		use self::UnavailableError::*;
		use self::CommunicationError::*;
		let error = match result
		{
			SCARD_W_RESET_CARD if self.connected_card.is_shared =>
			{
				self.connected_card.reconnect()?;
				
				return Ok(TransactionInterrupted(()))
			},
			
			SCARD_E_UNSUPPORTED_FEATURE => return Ok(Succeeded(None)),
			
			SCARD_E_NOT_TRANSACTED => DataExchangeWithCardFailed,
			
			SCARD_W_UNPOWERED_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered))),
			
			SCARD_W_UNRESPONSIVE_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute))),
			
			SCARD_W_REMOVED_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved))),
			
			SCARD_E_NO_SMARTCARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard))),
			
			SCARD_E_READER_UNAVAILABLE => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable))),
			
			SCARD_E_NO_MEMORY => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory))),
			
			SCARD_E_NO_SERVICE => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished))),
			
			SCARD_F_COMM_ERROR => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications))),
			
			SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
			
			SCARD_E_INSUFFICIENT_BUFFER => unimplemented!("Provided a non-null buffer that is not too big"),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Undocumented error {} from SCardGetAttrib()", result),
		};
		Err(error)
	}
	
	/// Tries to return `false` if the attribute is unsupported, but this may not be supported by internal behaviour.
	#[inline(always)]
	pub(crate) fn set_attribute(&self, attribute_identifier: AttributeIdentifier, attribute_value: &[u8]) -> Result<TransactedCommandOutcome<bool, ()>, CardTransmissionError>
	{
		let attribute_value_length = attribute_value.len();
		
		assert!(attribute_value_length <= MAX_BUFFER_SIZE, "attribute value is too big");
		
		let result = unsafe { SCardSetAttrib(self.connected_card.handle, attribute_identifier.into_DWORD(), attribute_value.as_ptr(), attribute_value_length as DWORD) };
		
		use self::TransactedCommandOutcome::*;
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			return Ok(Succeeded(true))
		}
		
		use self::CardTransmissionError::*;
		use self::CommunicationError::*;
		use self::ReconnectionUnavailableOrCommunicationError::*;
		use self::UnavailableOrCommunicationError::*;
		use self::UnavailableError::*;
		let error = match result
		{
			// Not defined in pcsclite documentation.
			SCARD_W_RESET_CARD if self.connected_card.is_shared =>
			{
				self.connected_card.reconnect()?;
				
				return Ok(TransactionInterrupted(()))
			},
			
			// Not defined in pcsclite documentation.
			SCARD_E_UNSUPPORTED_FEATURE => return Ok(Succeeded(false)),
			
			SCARD_E_NOT_TRANSACTED => DataExchangeWithCardFailed,
			
			SCARD_W_UNPOWERED_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered))),
			
			SCARD_W_UNRESPONSIVE_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute))),
			
			SCARD_W_REMOVED_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved))),
			
			SCARD_E_NO_SMARTCARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard))),
			
			SCARD_E_READER_UNAVAILABLE => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable))),
			
			SCARD_E_NO_MEMORY => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory))),
			
			SCARD_E_NO_SERVICE => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished))),
			
			SCARD_F_COMM_ERROR => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications))),
			
			SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
			
			SCARD_E_INVALID_VALUE => unreachable!("Provided suitable parameters"),
			
			SCARD_E_INVALID_PARAMETER => unreachable!("Provided non-null parameters"),
			
			SCARD_E_INSUFFICIENT_BUFFER => unimplemented!("Provided a non-null buffer that is not too big"),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Undocumented error {} from SCardSetAttrib()", result),
		};
		Err(error)
	}
	
	/// If sending normal APDUs, make sure `receive_buffer` is `MAX_BUFFER_SIZE`; if using extended APDUs, make sure it is `MAX_BUFFER_SIZE_EXTENDED`.
	#[inline(always)]
	pub(crate) fn transmit_apdu<'receive_buffer>(&self, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<TransactedCommandOutcome<&'receive_buffer [u8], ()>, CardCommandError>
	{
		debug_assert!(send_buffer.len() <= MAX_BUFFER_SIZE_EXTENDED);
		debug_assert!(receive_buffer.len() <= MAX_BUFFER_SIZE_EXTENDED);
		
		let pioSendPci = match self.connected_card.active_protocol()
		{
			None => panic!("Transmit is not supported for cards directly connected to"),
			
			Some(protocol) => protocol.get_protocol_pci()
		};
		
		let mut receive_buffer_length = receive_buffer.len() as DWORD;
		let result = unsafe { SCardTransmit(self.connected_card.handle, pioSendPci, send_buffer.as_ptr(), send_buffer.len() as DWORD, null_mut(), receive_buffer.as_mut_ptr() as *mut u8, &mut receive_buffer_length) };
		
		use self::TransactedCommandOutcome::*;
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			let receive_buffer_length = receive_buffer_length as usize;
			let slice = receive_buffer.get_unchecked_range_safe(.. receive_buffer_length);
			let receive_buffer = unsafe { MaybeUninit::slice_assume_init_ref(slice) };
			
			return Ok(Succeeded(receive_buffer))
		}
		
		use self::CardCommandError::*;
		use self::CardTransmissionError::*;
		use self::ReconnectionUnavailableOrCommunicationError::*;
		use self::UnavailableOrCommunicationError::*;
		use self::UnavailableError::*;
		use self::CommunicationError::*;
		let error = match result
		{
			SCARD_W_RESET_CARD if self.connected_card.is_shared =>
			{
				self.connected_card.reconnect()?;
				
				return Ok(TransactionInterrupted(()))
			},
			
			SCARD_E_INSUFFICIENT_BUFFER =>
			{
				let receive_buffer_length = receive_buffer_length as usize;
				ReceiveBufferIsTooSmall { minimum_size_required: receive_buffer_length  }
			},
			
			SCARD_E_NOT_TRANSACTED => CardTransmission(DataExchangeWithCardFailed),
			
			SCARD_W_UNPOWERED_CARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered)))),
			
			SCARD_W_UNRESPONSIVE_CARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute)))),
			
			SCARD_W_REMOVED_CARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved)))),
			
			SCARD_E_NO_SMARTCARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard)))),
			
			SCARD_E_READER_UNAVAILABLE => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable)))),
			
			SCARD_E_NO_MEMORY => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory)))),
			
			SCARD_E_NO_SERVICE => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)))),
			
			SCARD_F_COMM_ERROR => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications)))),
			
			SCARD_E_PROTO_MISMATCH => panic!("pioSendPci / pioRecvPci protocol mismatch; not sure how this is possible"),
			
			SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
			
			SCARD_E_INVALID_VALUE => unreachable!("Provided suitable parameters"),
			
			SCARD_E_INVALID_PARAMETER => unreachable!("Provided non-null parameters"),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Undocumented error {} from SCardSetAttrib()", result),
		};
		Err(error)
	}
	
	/// Sends a command directly to the IFD Handler (Card Reader driver) to be processed by the Card Reader.
	///
	/// Ideally, make sure `receive_buffer` is `MAX_BUFFER_SIZE_EXTENDED`.
	///
	/// The CCID project at <https://salsa.debian.org/rousseau/CCID.git> contains a partial list of control codes in [`SCARDCONTROL.txt`](https://salsa.debian.org/rousseau/CCID/-/blob/master/SCARDCONTOL.txt).
	pub(crate) fn transmit_control<'receive_buffer>(&self, control_code: u32, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<TransactedCommandOutcome<&'receive_buffer [u8], ()>, CardCommandError>
	{
		let mut bytes_returned: MaybeUninit<DWORD> = MaybeUninit::uninit();
		let result = unsafe { SCardControl(self.connected_card.handle, control_code as DWORD, send_buffer.as_ptr(), send_buffer.len() as DWORD, receive_buffer.as_mut_ptr() as *mut u8, receive_buffer.len() as DWORD, bytes_returned.as_mut_ptr()) };
		
		use self::TransactedCommandOutcome::*;
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			let receive_buffer_length = (unsafe { bytes_returned.assume_init() }) as usize;
			let slice = receive_buffer.get_unchecked_range_safe(.. receive_buffer_length);
			let receive_buffer = unsafe { MaybeUninit::slice_assume_init_ref(slice) };
			
			return Ok(Succeeded(receive_buffer))
		}
		
		use self::CardCommandError::*;
		use self::CardTransmissionError::*;
		use self::ReconnectionUnavailableOrCommunicationError::*;
		use self::UnavailableOrCommunicationError::*;
		use self::UnavailableError::*;
		use self::CommunicationError::*;
		let error = match result
		{
			SCARD_W_RESET_CARD if self.connected_card.is_shared =>
			{
				self.connected_card.reconnect()?;
				
				return Ok(TransactionInterrupted(()))
			},
			
			SCARD_E_INSUFFICIENT_BUFFER =>
			{
				let receive_buffer_length = (unsafe { bytes_returned.assume_init() }) as usize;
				ReceiveBufferIsTooSmall { minimum_size_required: receive_buffer_length  }
			},
			
			SCARD_E_NOT_TRANSACTED => CardTransmission(DataExchangeWithCardFailed),
			
			SCARD_W_UNPOWERED_CARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered)))),
			
			SCARD_W_UNRESPONSIVE_CARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute)))),
			
			SCARD_W_REMOVED_CARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved)))),
			
			SCARD_E_NO_SMARTCARD => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard)))),
			
			SCARD_E_READER_UNAVAILABLE => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable)))),
			
			SCARD_E_NO_MEMORY => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory)))),
			
			SCARD_E_NO_SERVICE => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)))),
			
			SCARD_F_COMM_ERROR => CardTransmission(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications)))),
			
			SCARD_E_PROTO_MISMATCH => panic!("pioSendPci / pioRecvPci protocol mismatch; not sure how this is possible"),
			
			SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
			
			SCARD_E_INVALID_VALUE => unreachable!("Provided suitable parameters"),
			
			SCARD_E_INVALID_PARAMETER => unreachable!("Provided non-null parameters"),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Undocumented error {} from SCardSetAttrib()", result),
		};
		Err(error)
	}
	
	#[inline(always)]
	pub(crate) fn end(mut self, end_transaction_disposition: CardDisposition) -> Result<TransactedCommandOutcome<(), ConnectedCard>, ReconnectionUnavailableOrCommunicationError>
	{
		self.disposed = true;
		let connected_card = unsafe { read(&self.connected_card) };
		drop(self);
		
		use self::TransactedCommandOutcome::*;
		
		let card_disposition = if connected_card.is_shared
		{
			let result = unsafe { SCardEndTransaction(connected_card.handle, end_transaction_disposition.into_DWORD()) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				CardDisposition::Leave
			}
			else
			{
				use self::ReconnectionUnavailableOrCommunicationError::*;
				use self::UnavailableOrCommunicationError::*;
				use self::UnavailableError::*;
				use self::CommunicationError::*;
				let error = match result
				{
					SCARD_E_SHARING_VIOLATION => return Ok(SharingViolation(connected_card)),
					
					// https://docs.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardendtransaction
					SCARD_W_RESET_CARD if connected_card.is_shared =>
					{
						connected_card.reconnect()?;
						
						return Ok(TransactionInterrupted(connected_card))
					},
					
					SCARD_W_UNPOWERED_CARD => UnavailableOrCommunication(Unavailable(CardIsUnpowered)),
					
					SCARD_W_UNRESPONSIVE_CARD => UnavailableOrCommunication(Unavailable(CardIsMute)),
					
					SCARD_W_REMOVED_CARD => UnavailableOrCommunication(Unavailable(CardRemoved)),
					
					SCARD_E_NO_SMARTCARD => UnavailableOrCommunication(Unavailable(NoCard)),
					
					SCARD_E_READER_UNAVAILABLE => UnavailableOrCommunication(Unavailable(CardReaderUnavailable)),
					
					SCARD_E_NO_MEMORY => UnavailableOrCommunication(Communication(OutOfMemory)),
					
					SCARD_E_NO_SERVICE => UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)),
					
					SCARD_F_COMM_ERROR => UnavailableOrCommunication(Communication(InternalCommunications)),
					
					SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					_ => unreachable!("Undocumented error {} from SCardEndTransaction()", result),
				};
				
				return Err(error)
			}
		}
		else
		{
			end_transaction_disposition
		};
		Ok(Succeeded(connected_card.disconnect(card_disposition)?))
	}
}
