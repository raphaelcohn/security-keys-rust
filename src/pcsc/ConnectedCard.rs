// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct ConnectedCard
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
	
	fn status<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(&self, card_status_user: CardStatusUser) -> Result<R, CardStatusError>
	{
		let mut reader_name: [MaybeUninit<u8>; MAX_READERNAME] = MaybeUninit::uninit_array();
		let mut state = MaybeUninit::uninit();
		let mut protocol = MaybeUninit::uninit();
		let mut answer_to_reset: [MaybeUninit<u8>; ATR_BUFFER_SIZE] = MaybeUninit::uninit_array();
		
		let mut remaining_retry_attempts = self.card_shared_access_back_off.remaining_retry_attempts;
		loop
		{
			let mut read_name_length = MAX_READERNAME as DWORD;
			let mut answer_to_reset_length = ATR_BUFFER_SIZE as DWORD;
			let result = unsafe { SCardStatus(self.handle, reader_name.as_mut_ptr() as *mut c_char, &mut read_name_length, state.as_mut_ptr(), protocol.as_mut_ptr(), answer_to_reset.as_mut_ptr() as *mut u8, &mut answer_to_reset_length) };
			
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
						if unlikely!(remaining_retry_attempts == 0)
						{
							return Err(TooManyRetries)
						}
						remaining_retry_attempts -= 1;
						
						self.reconnect()?;
						
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
					
					SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
					
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
	/// Begins a transaction.
	pub(crate) fn begin_transaction(self) -> Result<TransactedCommandOutcome<ConnectedCardTransaction, ConnectedCard>, ReconnectionUnavailableOrCommunicationError>
	{
		if self.is_shared
		{
			self.begin_shared_transaction()
		}
		else
		{
			self.begun_transaction()
		}
	}
	
	#[inline(always)]
	pub(crate) fn disconnect(mut self, card_disposition: CardDisposition) -> Result<(), UnavailableOrCommunicationError>
	{
		self.disposed = true;
		
		let ConnectedCard { handle, .. } = self;
		
		let result = unsafe { SCardDisconnect(handle, card_disposition.into_DWORD()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			Ok(())
		}
		else
		{
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
				
				SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardConnect()", result),
			};
			Err(error)
		}
	}
	
	#[inline(always)]
	fn begin_shared_transaction(self) -> Result<TransactedCommandOutcome<ConnectedCardTransaction, ConnectedCard>, ReconnectionUnavailableOrCommunicationError>
	{
		debug_assert!(self.is_shared);
		
		let result = unsafe { SCardBeginTransaction(self.handle) };
		if likely!(result == SCARD_S_SUCCESS)
		{
			return self.begun_transaction()
		}
		
		use self::TransactedCommandOutcome::*;
		use self::ReconnectionUnavailableOrCommunicationError::*;
		use self::UnavailableError::*;
		use self::UnavailableOrCommunicationError::*;
		use self::CommunicationError::*;
		
		let error = match result
		{
			SCARD_E_SHARING_VIOLATION => return Ok(SharingViolation(self)),
			
			SCARD_W_RESET_CARD if self.is_shared =>
			{
				self.reconnect()?;
				return Ok(TransactionInterrupted(self))
			}
			
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
			
			_ => unreachable!("Undocumented error {} from SCardConnect()", result),
		};
		
		Err(error)
	}
	
	#[inline(always)]
	fn begun_transaction(self) -> Result<TransactedCommandOutcome<ConnectedCardTransaction, ConnectedCard>, ReconnectionUnavailableOrCommunicationError>
	{
		Ok(TransactedCommandOutcome::Succeeded(ConnectedCardTransaction { connected_card: self, disposed: false }))
	}
	
	#[inline(always)]
	fn active_protocol_into_DWORD(&self) -> DWORD
	{
		match self.active_protocol()
		{
			None => 0,
			
			Some(protocol) => protocol.into_DWORD()
		}
	}
	
	// libpcsclite: Any PC/SC transaction held by the process is still valid after SCardReconnect().
	// windows: PC/SC transactions are released and a new call to SCardBeginTransaction() must be done.
	#[inline(always)]
	fn reconnect(&self) -> Result<(), CardConnectError>
	{
		debug_assert_eq!(self.is_shared, true);
		let (share_mode, dwPreferredProtocols) = match self.active_protocol()
		{
			None => (SCARD_SHARE_DIRECT, 0),
			
			Some(protocol) => (SCARD_SHARE_SHARED, protocol.into_DWORD())
		};
		let mut active_protocol = MaybeUninit::uninit();
		let mut card_shared_access_back_off = self.card_shared_access_back_off.clone();
		
		loop
		{
			let result = unsafe { SCardReconnect(self.handle, share_mode, dwPreferredProtocols, self.reconnect_card_disposition.into_DWORD(), active_protocol.as_mut_ptr()) };
			if likely!(result == SCARD_S_SUCCESS)
			{
				debug_assert_eq!(unsafe { active_protocol.assume_init() }, dwPreferredProtocols);
				break
			}
			else
			{
				use self::CardConnectError::*;
				use self::CommunicationError::*;
				use self::UnavailableError::*;
				use self::UnavailableOrCommunicationError::*;
				
				let error = match result
				{
					SCARD_E_SHARING_VIOLATION => if card_shared_access_back_off.sleep()
					{
						continue
					}
					else
					{
						GivingUpAsCanNotGetSharedAccess
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
					
					SCARD_E_PROTO_MISMATCH => unimplemented!("Protocols are validated before being passed"),
					
					SCARD_E_INVALID_PARAMETER => unreachable!("phCard and pdwActiveProtocol are not null"),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					_ => unreachable!("Undocumented error {} from SCardReconnect()", result),
				};
				return Err(error)
			}
		}
		self.active_protocol.set(unsafe { transmute(active_protocol.assume_init()) });
		Ok(())
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
