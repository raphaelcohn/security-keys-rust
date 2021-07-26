// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// A transaction on a `ConnectedCard`.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct ConnectedCardTransaction
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
	fn status_or_disconnect<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(self, card_status_user: CardStatusUser) -> Result<(Self, R), WithDisconnectError<CardStatusError>>
	{
		match self.status(card_status_user)
		{
			Err(cause) => self.disconnect_on_error(cause),
			
			Ok(ok) => Ok((self, ok))
		}
	}
	
	#[inline(always)]
	fn status<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(&self, card_status_user: CardStatusUser) -> Result<R, CardStatusError>
	{
		self.connected_card.status(card_status_user)
	}
}

impl ConnectedCardTransaction
{
	/// High-level API; generally the most useful.
	#[inline(always)]
	pub fn get_attribute_or_disconnect_activity<AttributeUser: for <'a> FnOnce(&'a [u8]) -> R, R>(self, attribute_identifier: AttributeIdentifier, attribute_user: AttributeUser) -> Result<(Self, Option<R>), ActivityError>
	{
		self.get_attribute_or_disconnect(attribute_identifier, attribute_user).map_err(|cause| ActivityError::GetAttribute { cause, attribute_identifier })
	}
	
	/// Mid-level API that ensures a card is properly disconnected.
	///
	/// Returns `None` if the attribute is unsupported.
	///
	/// The CCID project at <https://salsa.debian.org/rousseau/CCID.git> contains a partial list of attribute value formats in [`SCARDGETATTRIB.txt`](https://salsa.debian.org/rousseau/CCID/-/blob/master/SCARDGETATTRIB.txt).
	#[inline(always)]
	pub fn get_attribute_or_disconnect<AttributeUser: for <'a> FnOnce(&'a [u8]) -> R, R>(self, attribute_identifier: AttributeIdentifier, attribute_user: AttributeUser) -> Result<(Self, Option<R>), WithDisconnectError<CardTransmissionError>>
	{
		match self.get_attribute(attribute_identifier, attribute_user)
		{
			Err(cause) => self.disconnect_on_error(cause),
			
			Ok(ok) => Ok((self, ok))
		}
	}
	
	/// Returns `None` if the attribute is unsupported.
	#[inline(always)]
	pub fn get_attribute<AttributeUser: for <'a> FnOnce(&'a [u8]) -> R, R>(&self, attribute_identifier: AttributeIdentifier, attribute_user: AttributeUser) -> Result<Option<R>, CardTransmissionError>
	{
		let handle = self.handle();
		let attribute_identifier = attribute_identifier.into_DWORD();
		let mut attribute_value: [MaybeUninit<u8>; Context::MaximumAttributeValueSize] = MaybeUninit::uninit_array();
		let attribute_value_pointer = attribute_value.as_mut_ptr() as *mut u8;
		let mut attribute_length;
		
		let mut remaining_reset_retry_attempts = self.remaining_reset_retry_attempts();
		loop
		{
			attribute_length = attribute_value.len() as DWORD;
			let result = unsafe { SCardGetAttrib(handle, attribute_identifier, attribute_value_pointer, &mut attribute_length) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				let slice = attribute_value.get_unchecked_range_safe(..(attribute_length as usize));
				let attribute_value = unsafe { MaybeUninit::slice_assume_init_ref(slice) };
				return Ok(Some(attribute_user(attribute_value)))
			}
			
			use self::CardStatusError::*;
			use self::CardTransmissionError::*;
			use self::ReconnectionUnavailableOrCommunicationError::*;
			use self::UnavailableOrCommunicationError::*;
			use self::UnavailableError::*;
			use self::CommunicationError::*;
			let error = match result
			{
				SCARD_W_RESET_CARD if self.connected_card.is_shared =>
				{
					remaining_reset_retry_attempts.card_was_reset::<CardTransmissionError>(&self.connected_card)?;
					continue
				}
				
				SCARD_E_UNSUPPORTED_FEATURE => return Ok(None),
				
				SCARD_E_NOT_TRANSACTED => DataExchangeWithCardFailed,
				
				SCARD_W_UNPOWERED_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered)))),
				
				SCARD_W_UNRESPONSIVE_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute)))),
				
				SCARD_W_REMOVED_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved)))),
				
				SCARD_E_NO_SMARTCARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard)))),
				
				SCARD_E_READER_UNAVAILABLE => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable)))),
				
				SCARD_E_NO_MEMORY => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory)))),
				
				SCARD_E_NO_SERVICE => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)))),
				
				SCARD_F_COMM_ERROR => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications)))),
				
				SCARD_F_INTERNAL_ERROR => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalError)))),
				
				SCARD_E_INSUFFICIENT_BUFFER => unimplemented!("Provided a non-null buffer that is not too big"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardGetAttrib()", result),
			};
			return Err(error)
		}
	}
	
	/// High-level API; generally the most useful.
	#[inline(always)]
	pub fn set_attribute_or_disconnect_activity(self, attribute_identifier: AttributeIdentifier, attribute_value: &ArrayVec<u8, MaximumAttributeValueSize>) -> Result<(Self, bool), ActivityError>
	{
		self.set_attribute_or_disconnect(attribute_identifier, attribute_value).map_err(|cause| ActivityError::SetAttribute { cause, attribute_identifier })
	}
	
	/// Mid-level API that ensures a card is properly disconnected.
	#[inline(always)]
	pub fn set_attribute_or_disconnect(self, attribute_identifier: AttributeIdentifier, attribute_value: &ArrayVec<u8, MaximumAttributeValueSize>) -> Result<(Self, bool), WithDisconnectError<CardTransmissionError>>
	{
		match self.set_attribute(attribute_identifier, attribute_value)
		{
			Err(cause) => self.disconnect_on_error(cause),
			
			Ok(ok) => Ok((self, ok))
		}
	}
	
	/// Tries to return `false` if the attribute is unsupported, but this may not be supported by internal behaviour.
	#[inline(always)]
	pub fn set_attribute(&self, attribute_identifier: AttributeIdentifier, attribute_value: &ArrayVec<u8, MaximumAttributeValueSize>) -> Result<bool, CardTransmissionError>
	{
		let handle = self.handle();
		let attribute_identifier = attribute_identifier.into_DWORD();
		let attribute_value_pointer = attribute_value.as_ptr();
		let attribute_value_length =
		{
			let attribute_value_length = attribute_value.len();
			assert!(attribute_value_length <= Context::MaximumSendOrReceiveBufferSize, "attribute value is too big");
			attribute_value_length as DWORD
		};
		
		let mut remaining_reset_retry_attempts = self.remaining_reset_retry_attempts();
		loop
		{
			let result = unsafe { SCardSetAttrib(handle, attribute_identifier, attribute_value_pointer, attribute_value_length) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				return Ok(true)
			}
			
			use self::CardStatusError::*;
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
					remaining_reset_retry_attempts.card_was_reset::<CardTransmissionError>(&self.connected_card)?;
					continue
				}
				
				// Not defined in pcsclite documentation.
				SCARD_E_UNSUPPORTED_FEATURE => return Ok(false),
				
				SCARD_E_NOT_TRANSACTED => DataExchangeWithCardFailed,
				
				SCARD_W_UNPOWERED_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered)))),
				
				SCARD_W_UNRESPONSIVE_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute)))),
				
				SCARD_W_REMOVED_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved)))),
				
				SCARD_E_NO_SMARTCARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard)))),
				
				SCARD_E_READER_UNAVAILABLE => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable)))),
				
				SCARD_E_NO_MEMORY => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory)))),
				
				SCARD_E_NO_SERVICE => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)))),
				
				SCARD_F_COMM_ERROR => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications)))),
				
				SCARD_F_INTERNAL_ERROR => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalError)))),
				
				SCARD_E_INVALID_VALUE => unreachable!("Provided suitable parameters"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("Provided non-null parameters"),
				
				SCARD_E_INSUFFICIENT_BUFFER => unimplemented!("Provided a non-null buffer that is not too big"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardSetAttrib()", result),
			};
			return Err(error)
		}
	}
	
	/// High-level API; generally the most useful.
	#[inline(always)]
	pub fn transmit_application_protocol_data_unit_or_disconnect_activity<'receive_buffer>(self, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<(Self, &'receive_buffer [u8]), ActivityError>
	{
		self.transmit_application_protocol_data_unit_or_disconnect(send_buffer, receive_buffer).map_err(|cause| ActivityError::TransmitApplicationProtocolDataUnit { cause, class: send_buffer[0], instruction: send_buffer[1], parameters: [send_buffer[2], send_buffer[3]] })
	}
	
	/// Mid-level API that ensures a card is properly disconnected.
	#[inline(always)]
	pub fn transmit_application_protocol_data_unit_or_disconnect<'receive_buffer>(self, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<(Self, &'receive_buffer [u8]), WithDisconnectError<CardCommandError>>
	{
		match self.transmit_application_protocol_data_unit(send_buffer, receive_buffer)
		{
			Err(cause) => self.disconnect_on_error(cause),
			
			Ok(ok) => Ok((self, ok))
		}
	}
	
	/// If sending normal APDUs, make sure `receive_buffer` is `Context::MaximumSendOrReceiveBufferSize`; if using extended APDUs, make sure it is `Context::MaximumExtendedSendOrReceiveBufferSize`.
	pub fn transmit_application_protocol_data_unit<'receive_buffer>(&self, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<&'receive_buffer [u8], CardCommandError>
	{
		let send_buffer_length = send_buffer.len();
		let receive_buffer_length_original = receive_buffer.len();
		
		const ApplicationProtocolDataUnitHeaderSize: usize = 4;
		debug_assert!(send_buffer_length > ApplicationProtocolDataUnitHeaderSize);
		debug_assert!(send_buffer_length <= Context::MaximumExtendedSendOrReceiveBufferSize);
		debug_assert!(receive_buffer_length_original <= Context::MaximumExtendedSendOrReceiveBufferSize);
		
		let handle = self.handle();
		let pioSendPci = match self.connected_card.active_protocol()
		{
			None => panic!("Transmit is not supported for cards directly connected to"),
			
			Some(protocol) => protocol.get_protocol_pci()
		};
		let send_buffer_pointer = send_buffer.as_ptr();
		let send_buffer_length = send_buffer_length as DWORD;
		let receive_buffer_pointer = receive_buffer.as_mut_ptr() as *mut u8;
		let mut receive_buffer_length;
		
		let mut remaining_reset_retry_attempts = self.remaining_reset_retry_attempts();
		loop
		{
			receive_buffer_length = receive_buffer_length_original as DWORD;
			let result = unsafe { SCardTransmit(handle, pioSendPci, send_buffer_pointer, send_buffer_length, null_mut(), receive_buffer_pointer, &mut receive_buffer_length) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				let receive_buffer_length = receive_buffer_length as usize;
				let slice = receive_buffer.get_unchecked_range_safe(.. receive_buffer_length);
				let receive_buffer = unsafe { MaybeUninit::slice_assume_init_ref(slice) };
				
				return Ok(receive_buffer)
			}
			
			use self::CardCommandError::*;
			use self::CardStatusError::*;
			use self::CardTransmissionError::*;
			use self::ReconnectionUnavailableOrCommunicationError::*;
			use self::UnavailableOrCommunicationError::*;
			use self::UnavailableError::*;
			use self::CommunicationError::*;
			let error = match result
			{
				SCARD_W_RESET_CARD if self.connected_card.is_shared =>
				{
					remaining_reset_retry_attempts.card_was_reset::<CardCommandError>(&self.connected_card)?;
					continue
				}
				
				SCARD_E_INSUFFICIENT_BUFFER =>
				{
					let receive_buffer_length = receive_buffer_length as usize;
					ReceiveBufferIsTooSmall { minimum_size_required: receive_buffer_length  }
				}
				
				SCARD_E_NOT_TRANSACTED => CardTransmission(DataExchangeWithCardFailed),
				
				SCARD_W_UNPOWERED_CARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered))))),
				
				SCARD_W_UNRESPONSIVE_CARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute))))),
				
				SCARD_W_REMOVED_CARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved))))),
				
				SCARD_E_NO_SMARTCARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard))))),
				
				SCARD_E_READER_UNAVAILABLE => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable))))),
				
				SCARD_E_NO_MEMORY => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory))))),
				
				SCARD_E_NO_SERVICE => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished))))),
				
				SCARD_F_COMM_ERROR => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications))))),
				
				SCARD_F_INTERNAL_ERROR => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalError))))),
				
				SCARD_E_PROTO_MISMATCH => panic!("pioSendPci / pioRecvPci protocol mismatch; not sure how this is possible"),
				
				SCARD_E_INVALID_VALUE => unreachable!("Provided suitable parameters"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("Provided non-null parameters"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardSetAttrib()", result),
			};
			return Err(error)
		}
	}
	
	/// High-level API; generally the most useful.
	#[inline(always)]
	pub fn transmit_control_or_disconnect_activity<'receive_buffer>(self, control_code: ControlCode, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<(Self, &'receive_buffer [u8]), ActivityError>
	{
		self.transmit_application_protocol_data_unit_or_disconnect(send_buffer, receive_buffer).map_err(|cause| ActivityError::TransmitControl { cause, control_code })
	}
	
	/// Mid-level API that ensures a card is properly disconnected.
	#[inline(always)]
	pub fn transmit_control_or_disconnect<'receive_buffer>(self, control_code: ControlCode, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<(Self, &'receive_buffer [u8]), WithDisconnectError<CardCommandError>>
	{
		match self.transmit_control(control_code, send_buffer, receive_buffer)
		{
			Err(cause) => self.disconnect_on_error(cause),
			
			Ok(ok) => Ok((self, ok))
		}
	}
	
	/// Sends a command directly to the IFD Handler (Card Reader driver) to be processed by the Card Reader.
	///
	/// Ideally, make sure `receive_buffer` is `Context::MaximumSendOrReceiveBufferSizeExtended`.
	pub fn transmit_control<'receive_buffer>(&self, control_code: ControlCode, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [MaybeUninit<u8>]) -> Result<&'receive_buffer [u8], CardCommandError>
	{
		let send_buffer_length = send_buffer.len();
		debug_assert!(send_buffer_length <= Context::MaximumExtendedSendOrReceiveBufferSize);
		
		let receive_buffer_length = receive_buffer.len();
		debug_assert!(receive_buffer_length <= Context::MaximumExtendedSendOrReceiveBufferSize);
		
		let handle = self.handle();
		let control_code = control_code.into_DWORD();
		let send_buffer_pointer = send_buffer.as_ptr();
		let send_buffer_length = send_buffer.len() as DWORD;
		let receive_buffer_pointer = receive_buffer.as_mut_ptr() as *mut u8;
		let receive_buffer_length = receive_buffer_length as DWORD;
		let mut bytes_returned: MaybeUninit<DWORD> = MaybeUninit::uninit();
		let bytes_returned_pointer = bytes_returned.as_mut_ptr();
		
		let mut remaining_reset_retry_attempts = self.remaining_reset_retry_attempts();
		loop
		{
			let result = unsafe { SCardControl(handle, control_code, send_buffer_pointer, send_buffer_length, receive_buffer_pointer, receive_buffer_length, bytes_returned_pointer) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				let receive_buffer_length = (unsafe { bytes_returned.assume_init() }) as usize;
				let slice = receive_buffer.get_unchecked_range_safe(.. receive_buffer_length);
				let receive_buffer = unsafe { MaybeUninit::slice_assume_init_ref(slice) };
				
				return Ok(receive_buffer)
			}
			
			use self::CardCommandError::*;
			use self::CardStatusError::*;
			use self::CardTransmissionError::*;
			use self::ReconnectionUnavailableOrCommunicationError::*;
			use self::UnavailableOrCommunicationError::*;
			use self::UnavailableError::*;
			use self::CommunicationError::*;
			let error = match result
			{
				SCARD_W_RESET_CARD if self.connected_card.is_shared =>
				{
					remaining_reset_retry_attempts.card_was_reset::<CardCommandError>(&self.connected_card)?;
					continue
				}
				
				SCARD_E_INSUFFICIENT_BUFFER =>
				{
					let receive_buffer_length = (unsafe { bytes_returned.assume_init() }) as usize;
					ReceiveBufferIsTooSmall { minimum_size_required: receive_buffer_length  }
				},
				
				SCARD_E_NOT_TRANSACTED => CardTransmission(DataExchangeWithCardFailed),
				
				SCARD_W_UNPOWERED_CARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered))))),
				
				SCARD_W_UNRESPONSIVE_CARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute))))),
				
				SCARD_W_REMOVED_CARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved))))),
				
				SCARD_E_NO_SMARTCARD => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard))))),
				
				SCARD_E_READER_UNAVAILABLE => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable))))),
				
				SCARD_E_NO_MEMORY => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory))))),
				
				SCARD_E_NO_SERVICE => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished))))),
				
				SCARD_F_COMM_ERROR => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications))))),
				
				SCARD_F_INTERNAL_ERROR => CardTransmission(CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalError))))),
				
				SCARD_E_PROTO_MISMATCH => panic!("pioSendPci / pioRecvPci protocol mismatch; not sure how this is possible"),
				
				SCARD_E_INVALID_VALUE => unreachable!("Provided suitable parameters"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("Provided non-null parameters"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardSetAttrib()", result),
			};
			return Err(error)
		}
	}
	
	/// High-level API; generally the most useful.
	#[inline(always)]
	pub fn end_and_disconnect_activity(self, end_transaction_disposition: CardDisposition) -> Result<(), ActivityError>
	{
		self.end_and_disconnect(end_transaction_disposition).map_err(|cause| ActivityError::EndTransaction { cause, end_transaction_disposition })
	}
	
	/// Mid-level API that ensures a card is properly disconnected.
	#[inline(always)]
	pub fn end_and_disconnect(mut self, end_transaction_disposition: CardDisposition) -> Result<(), WithDisconnectError<TransactionError>>
	{
		self.disposed = true;
		let connected_card = unsafe { read(&self.connected_card) };
		drop(self);
		
		let (connected_card, card_disposition) = if connected_card.is_shared
		{
			let connected_card = Self::end_shared_and_disconnect_if_error_occurs(connected_card, end_transaction_disposition)?;
			(connected_card, CardDisposition::Leave)
		}
		else
		{
			(connected_card, end_transaction_disposition)
		};
		connected_card.disconnect(card_disposition).map_err(|disconnect_error| WithDisconnectError::new(TransactionError::from(disconnect_error), Ok(())))
	}
	
	#[inline(always)]
	fn end_shared_and_disconnect_if_error_occurs(connected_card: ConnectedCard, end_transaction_disposition: CardDisposition) -> Result<ConnectedCard, WithDisconnectError<TransactionError>>
	{
		debug_assert!(connected_card.is_shared);
		
		let mut remaining_reset_retry_attempts = connected_card.remaining_reset_retry_attempts();
		loop
		{
			let result = unsafe { SCardEndTransaction(connected_card.handle, end_transaction_disposition.into_DWORD()) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				return Ok(connected_card)
			}
			
			use self::CardStatusError::*;
			use self::CommunicationError::*;
			use self::ReconnectionUnavailableOrCommunicationError::*;
			use self::TransactionError::*;
			use self::UnavailableOrCommunicationError::*;
			use self::UnavailableError::*;
			let error = match result
			{
				SCARD_W_RESET_CARD if connected_card.is_shared => match remaining_reset_retry_attempts.card_was_reset::<TransactionError>(&connected_card)
				{
					Err(error) => error,
					
					Ok(()) => continue,
				},
				
				SCARD_E_SHARING_VIOLATION => SharingViolation,
				
				SCARD_W_UNPOWERED_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered)))),
				
				SCARD_W_UNRESPONSIVE_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute)))),
				
				SCARD_W_REMOVED_CARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved)))),
				
				SCARD_E_NO_SMARTCARD => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard)))),
				
				SCARD_E_READER_UNAVAILABLE => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable)))),
				
				SCARD_E_NO_MEMORY => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory)))),
				
				SCARD_E_NO_SERVICE => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)))),
				
				SCARD_F_COMM_ERROR => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications)))),
				
				SCARD_F_INTERNAL_ERROR => CardStatus(ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalError)))),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardEndTransaction()", result),
			};
			
			let disconnect_error = connected_card.disconnect(CardDisposition::Leave);
			
			return Err(WithDisconnectError::new(error, disconnect_error))
		}
	}
	
	#[inline(always)]
	fn disconnect_on_error<R, E: error::Error>(mut self, cause: E) -> Result<R, WithDisconnectError<E>>
	{
		self.disposed = true;
		
		let connected_card = unsafe { read(&self.connected_card) };
		drop(self);
		
		connected_card.disconnect_on_error(cause)
	}
	
	#[inline(always)]
	const fn handle(&self) -> SCARDHANDLE
	{
		self.connected_card.handle
	}
	
	#[inline(always)]
	const fn remaining_reset_retry_attempts(&self) -> RemainingResetRetryAttempts
	{
		self.connected_card.remaining_reset_retry_attempts()
	}
}
