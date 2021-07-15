// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A card in a read that is connected.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct ConnectedCard
{
	handle: SCARDHANDLE,
	
	/// If there is no active protocol, the card reader is directly connected and `SCardTransmit()` will not work.
	active_protocol: Cell<Option<Protocol>>,
	
	is_shared: bool,
	
	card_shared_access_back_off: CardSharedAccessBackOff,
	
	reconnect_card_disposition: CardDisposition,
	
	disposed: bool,
}

impl Drop for ConnectedCard
{
	#[inline(always)]
	fn drop(&mut self)
	{
		assert!(self.disposed, "Card was not disconnected")
	}
}

impl ConnectedCardOrTransaction for ConnectedCard
{
	#[inline(always)]
	fn active_protocol(&self) -> Option<Protocol>
	{
		self.active_protocol.get()
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
	
	fn status<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(&self, card_status_user: CardStatusUser) -> Result<R, CardStatusError>
	{
		let mut reader_name: [MaybeUninit<u8>; MAX_READERNAME] = MaybeUninit::uninit_array();
		let reader_name_pointer = reader_name.as_mut_ptr() as *mut c_char;
		let mut read_name_length;
		let mut state = MaybeUninit::uninit();
		let state_pointer = state.as_mut_ptr();
		let mut protocol = MaybeUninit::uninit();
		let protocol_pointer = protocol.as_mut_ptr();
		let mut answer_to_reset: [MaybeUninit<u8>; ATR_BUFFER_SIZE] = MaybeUninit::uninit_array();
		let answer_to_reset_pointer = answer_to_reset.as_mut_ptr() as *mut u8;
		let mut answer_to_reset_length;
		
		let mut remaining_reset_retry_attempts = self.remaining_reset_retry_attempts();
		loop
		{
			read_name_length = MAX_READERNAME as DWORD;
			answer_to_reset_length = ATR_BUFFER_SIZE as DWORD;
			let result = unsafe { SCardStatus(self.handle, reader_name_pointer, &mut read_name_length, state_pointer, protocol_pointer, answer_to_reset_pointer, &mut answer_to_reset_length) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				let reader_name = CardReaderName::wrap_buffer(unsafe { MaybeUninit::slice_assume_init_ref(reader_name.get_unchecked_range_safe(.. (read_name_length as usize))) }, 0);
				let (insertions_and_removals_count, card_reader_statuses) = Self::process_state_from_status(state);
				let protocol: Protocol = unsafe { transmute(protocol.assume_init()) };
				let answer_to_reset = AnswerToReset(unsafe { MaybeUninit::slice_assume_init_ref(answer_to_reset.get_unchecked_range_safe(.. (answer_to_reset_length as usize))) });
				return Ok(card_status_user(reader_name, insertions_and_removals_count, card_reader_statuses, protocol, answer_to_reset))
			}
			else
			{
				use self::CardStatusError::*;
				use self::ReconnectionUnavailableOrCommunicationError::*;
				use self::UnavailableError::*;
				use self::UnavailableOrCommunicationError::*;
				use self::CommunicationError::*;
				
				let error = match result
				{
					SCARD_W_RESET_CARD if self.is_shared =>
					{
						remaining_reset_retry_attempts.card_was_reset::<CardStatusError>(self)?;
						continue
					}
					
					SCARD_W_UNPOWERED_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsUnpowered))),
					
					SCARD_W_UNRESPONSIVE_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardIsMute))),
					
					SCARD_W_REMOVED_CARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardRemoved))),
					
					SCARD_E_NO_SMARTCARD => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(NoCard))),
					
					SCARD_E_READER_UNAVAILABLE => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Unavailable(CardReaderUnavailable))),
					
					SCARD_E_NO_MEMORY => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(OutOfMemory))),
					
					SCARD_E_NO_SERVICE => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished))),
					
					SCARD_F_COMM_ERROR => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalCommunications))),
					
					SCARD_F_INTERNAL_ERROR => ReconnectionUnavailableOrCommunication(UnavailableOrCommunication(Communication(InternalError))),
					
					SCARD_E_INSUFFICIENT_BUFFER => unreachable!("The maximum buffer was provided for both reader_name and answer_to_reset"),
					
					SCARD_E_INVALID_PARAMETER => unreachable!("pcchReaderLen or pcbAtrLen are not null"),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					_ => unreachable!("Undocumented error {} from SCardReconnect()", result),
				};
				return Err(error)
			}
		}
	}
}

impl ConnectedCard
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn disconnect(mut self, card_disposition: CardDisposition) -> Result<(), UnavailableOrCommunicationError>
	{
		self.disposed = true;
		
		let ConnectedCard { handle, .. } = self;
		
		let result = unsafe { SCardDisconnect(handle, card_disposition.into_DWORD()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			return Ok(())
		}
		
		use self::CommunicationError::*;
		use self::UnavailableError::*;
		use self::UnavailableOrCommunicationError::*;
		
		let error = match result
		{
			SCARD_W_UNPOWERED_CARD => Unavailable(CardIsUnpowered),
			
			SCARD_W_UNRESPONSIVE_CARD => Unavailable(CardIsMute),
			
			SCARD_W_REMOVED_CARD => Unavailable(CardRemoved),
			
			SCARD_E_NO_SMARTCARD => Unavailable(NoCard),
			
			SCARD_E_READER_UNAVAILABLE => Unavailable(CardReaderUnavailable),
			
			SCARD_E_NO_MEMORY => Communication(OutOfMemory),
			
			SCARD_E_NO_SERVICE => Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
			
			SCARD_F_COMM_ERROR => Communication(InternalCommunications),
			
			SCARD_F_INTERNAL_ERROR => Communication(InternalError),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Undocumented error {} from SCardConnect()", result),
		};
		Err(error)
	}
	
	/// Begins a transaction or disconnects.
	#[inline(always)]
	pub fn begin_transaction_or_disconnect_activity(self) -> Result<ConnectedCardTransaction, ActivityError>
	{
		self.begin_transaction_or_disconnect().map_err(ActivityError::BeginTransaction)
	}
	
	/// Begins a transaction or disconnects.
	#[inline(always)]
	pub fn begin_transaction_or_disconnect(self) -> Result<ConnectedCardTransaction, WithDisconnectError<TransactionError>>
	{
		if self.is_shared
		{
			match self.begin_shared_transaction()
			{
				Err((this, cause)) => this.disconnect_on_error(cause),
				
				Ok(transaction) => Ok(transaction)
			}
		}
		else
		{
			Ok(self.begun_transaction())
		}
	}
	
	/// Begins a transaction.
	pub fn begin_transaction(self) -> Result<ConnectedCardTransaction, TransactionError>
	{
		if self.is_shared
		{
			self.begin_shared_transaction().map_err(|(_, error)| error)
		}
		else
		{
			Ok(self.begun_transaction())
		}
	}
	
	#[inline(always)]
	fn begin_shared_transaction(self) -> Result<ConnectedCardTransaction, (Self, TransactionError)>
	{
		debug_assert!(self.is_shared);
		
		let mut remaining_reset_retry_attempts = self.remaining_reset_retry_attempts();
		loop
		{
			let result = unsafe { SCardBeginTransaction(self.handle) };
			if likely!(result == SCARD_S_SUCCESS)
			{
				return Ok(self.begun_transaction())
			}
			
			use self::CardStatusError::*;
			use self::ReconnectionUnavailableOrCommunicationError::*;
			use self::TransactionError::*;
			use self::UnavailableError::*;
			use self::UnavailableOrCommunicationError::*;
			use self::CommunicationError::*;
			
			let error = match result
			{
				SCARD_W_RESET_CARD if self.is_shared =>
				{
					if let Err(error) = remaining_reset_retry_attempts.card_was_reset::<TransactionError>(&self)
					{
						return Err((self, error))
					}
					
					continue
				}
				
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
				
				_ => unreachable!("Undocumented error {} from SCardConnect()", result),
			};
			
			return Err((self, error))
		}
	}
	
	#[inline(always)]
	fn begun_transaction(self) -> ConnectedCardTransaction
	{
		ConnectedCardTransaction { connected_card: self, disposed: false }
	}
	
	#[inline(always)]
	const fn remaining_reset_retry_attempts(&self) -> RemainingResetRetryAttempts
	{
		self.card_shared_access_back_off.remaining_reset_retry_attempts()
	}
	
	#[inline(always)]
	fn reconnect(&self) -> Result<(), ConnectCardError>
	{
		debug_assert_eq!(self.is_shared, true);
		
		let (share_mode, dwPreferredProtocols) = match self.active_protocol()
		{
			None => (SCARD_SHARE_DIRECT, 0),
			
			Some(protocol) => (SCARD_SHARE_SHARED, protocol.into_DWORD())
		};
		let initialization = self.reconnect_card_disposition.into_DWORD();
		let mut active_protocol = MaybeUninit::uninit();
		let active_protocol_pointer = active_protocol.as_mut_ptr();
		let mut card_shared_access_back_off = self.card_shared_access_back_off.clone();
		loop
		{
			let result = unsafe { SCardReconnect(self.handle, share_mode, dwPreferredProtocols, initialization, active_protocol_pointer) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				debug_assert_eq!(unsafe { active_protocol.assume_init() }, dwPreferredProtocols);
				self.active_protocol.set(unsafe { transmute(active_protocol.assume_init()) });
				return Ok(())
			}
			
			use self::ConnectCardError::*;
			use self::CommunicationError::*;
			use self::UnavailableError::*;
			use self::UnavailableOrCommunicationError::*;
			
			let error = match result
			{
				SCARD_E_SHARING_VIOLATION =>
				{
					card_shared_access_back_off.reconnect_back_off_and_sleep()?;
					continue
				}
				
				SCARD_W_UNPOWERED_CARD => UnavailableOrCommunication(Unavailable(CardIsUnpowered)),
				
				SCARD_W_UNRESPONSIVE_CARD => UnavailableOrCommunication(Unavailable(CardIsMute)),
				
				SCARD_W_REMOVED_CARD => UnavailableOrCommunication(Unavailable(CardRemoved)),
				
				SCARD_E_NO_SMARTCARD => UnavailableOrCommunication(Unavailable(NoCard)),
				
				SCARD_E_READER_UNAVAILABLE => UnavailableOrCommunication(Unavailable(CardReaderUnavailable)),
				
				SCARD_E_NO_MEMORY => UnavailableOrCommunication(Communication(OutOfMemory)),
				
				SCARD_E_NO_SERVICE => UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)),
				
				SCARD_F_COMM_ERROR => UnavailableOrCommunication(Communication(InternalCommunications)),
				
				SCARD_F_INTERNAL_ERROR => UnavailableOrCommunication(Communication(InternalError)),
				
				SCARD_E_PROTO_MISMATCH => unimplemented!("Protocols are validated before being passed"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("phCard and pdwActiveProtocol are not null"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardReconnect()", result),
			};
			return Err(error)
		}
	}
	
	#[inline(always)]
	fn disconnect_on_error<R, E: error::Error>(self, cause: E) -> Result<R, WithDisconnectError<E>>
	{
		let disconnect_error = self.disconnect(CardDisposition::Leave);
		Err(WithDisconnectError::new(cause, disconnect_error))
	}
	
	#[inline(always)]
	fn process_state_from_status(state: MaybeUninit<DWORD>) -> (InsertionsAndRemovalsCount, HashSet<CardStatus>)
	{
		let state = unsafe { state.assume_init() };
		let insertions_and_removals_count = ((state as u32) >> 16) as u16;
		let enumeration_on_windows_and_bit_field_on_pcsclite = (state & 0xFFFF) as u16;
		let card_reader_statuses = CardStatus::convert(enumeration_on_windows_and_bit_field_on_pcsclite);
		(insertions_and_removals_count, card_reader_statuses)
	}
}
